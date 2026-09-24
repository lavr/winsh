package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// laneRecorder routes every exchange to one fake server while recording
// which connection carried which WinRM action.
type laneRecorder struct {
	mu      sync.Mutex
	actions map[string][]string
	closed  atomic.Int32
}

func soapAction(body string) string {
	for _, a := range []struct{ uri, name string }{
		{transferURI + "Create", "Create"}, {shellURI + "Command", "Command"}, {shellURI + "Send", "Send"},
		{shellURI + "Receive", "Receive"}, {shellURI + "Signal", "Signal"}, {transferURI + "Delete", "Delete"},
	} {
		if strings.Contains(body, a.uri) {
			return a.name
		}
	}
	return "?"
}

func (r *laneRecorder) lane(name string, post func(context.Context, string) (string, error)) postFunc {
	return func(ctx context.Context, body string) (string, error) {
		r.mu.Lock()
		if r.actions == nil {
			r.actions = map[string][]string{}
		}
		r.actions[name] = append(r.actions[name], soapAction(body))
		r.mu.Unlock()
		return post(ctx, body)
	}
}

func (r *laneRecorder) lanes(post func(context.Context, string) (string, error)) dataLanes {
	return func(context.Context) (poster, poster, func(), error) {
		return r.lane("send", post), r.lane("receive", post), func() { r.closed.Add(1) }, nil
	}
}

func (r *laneRecorder) only(t *testing.T, lane string, allowed ...string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.actions[lane]) == 0 {
		t.Fatalf("%s lane unused", lane)
	}
	for _, action := range r.actions[lane] {
		ok := false
		for _, a := range allowed {
			ok = ok || action == a
		}
		if !ok {
			t.Fatalf("%s lane carried %s: %v", lane, action, r.actions[lane])
		}
	}
}

func TestUploadUsesSeparateDataLanes(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	f := &uploadFake{receiverStdout: `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`, finalizerStdout: "OK: committed"}
	var r laneRecorder
	result, err := uploadLanes(t.Context(), req, nil, r.lane("control", f.post), r.lanes(f.post))
	if err != nil || !result.Committed {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	r.only(t, "send", "Send")
	r.only(t, "receive", "Receive")
	r.only(t, "control", "Create", "Command", "Send", "Receive", "Delete")
	if r.closed.Load() != 1 {
		t.Fatalf("data lanes closed %d times", r.closed.Load())
	}
}

func TestUploadStopsSendingWhenReceiverExitsEarly(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	f := &uploadFake{receiverEarly: true}
	var sends atomic.Int32
	send := func(ctx context.Context, body string) (string, error) {
		// Every Send blocks until the upload cancels it.
		sends.Add(1)
		<-ctx.Done()
		return "", ctx.Err()
	}
	lanes := func(context.Context) (poster, poster, func(), error) {
		return postFunc(send), postFunc(f.post), func() {}, nil
	}
	result, err := uploadLanes(t.Context(), req, nil, postFunc(f.post), lanes)
	if err == nil || !strings.Contains(err.Error(), "receiver exited before end of input") || result.Committed {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if sends.Load() != 1 {
		t.Fatalf("sent %d chunks after the receiver exited", sends.Load())
	}
}

func TestTransferLaneAuthenticationFailureStartsNoShell(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	var creates atomic.Int32
	p := postFunc(func(ctx context.Context, body string) (string, error) {
		if soapAction(body) == "Create" {
			creates.Add(1)
		}
		return "", errors.New("unexpected exchange")
	})
	lanes := func(context.Context) (poster, poster, func(), error) {
		return nil, nil, nil, errors.New("NTLM authentication failed: HTTP 401")
	}
	_, err := uploadLanes(t.Context(), req, nil, p, lanes)
	if err == nil || !strings.Contains(err.Error(), "authenticate data connections") || creates.Load() != 0 {
		t.Fatalf("upload err=%v creates=%d", err, creates.Load())
	}
	// Download resolves its remote temp directory through the control
	// connection first; no sender shell may follow the lane failure.
	f := &downloadFake{}
	control := postFunc(func(ctx context.Context, body string) (string, error) {
		if soapAction(body) == "Create" {
			creates.Add(1)
		}
		return f.post(ctx, body)
	})
	dest := filepath.Join(t.TempDir(), "download.bin")
	_, err = downloadLanes(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, control, lanes)
	if err == nil || !strings.Contains(err.Error(), "authenticate data connections") || creates.Load() != 1 {
		t.Fatalf("download err=%v creates=%d", err, creates.Load())
	}
}

func TestDownloadUsesSeparateDataLanes(t *testing.T) {
	data := []byte("lane data\x00\xff")
	h := sha256.Sum256(data)
	f := &downloadFake{data: base64.StdEncoding.EncodeToString(data) + "\r\n", record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":%d,"sha256":"%s"}`, len(data), hex.EncodeToString(h[:]))}
	var r laneRecorder
	dest := filepath.Join(t.TempDir(), "download.bin")
	_, err := downloadLanes(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, r.lane("control", f.post), r.lanes(f.post))
	if err != nil {
		t.Fatal(err)
	}
	r.only(t, "send", "Send")
	r.only(t, "receive", "Receive")
	if r.closed.Load() != 1 {
		t.Fatalf("data lanes closed %d times", r.closed.Load())
	}
}

// TestTransferLanesPyspnegoInterop drives one WinRS session over real NTLM:
// Create, Command and Delete use short-lived connections, while Send and
// Receive run concurrently on two persistent lanes. Receive sees sealed
// HTTP 500 OperationTimeout faults until EOF and keeps polling on the same
// connection, so each lane authenticates exactly once.
func TestTransferLanesPyspnegoInterop(t *testing.T) {
	if os.Getenv("WINSH_TEST_PYSPNEGO") != "1" {
		t.Skip("set WINSH_TEST_PYSPNEGO=1 after installing pyspnego")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	endpoint := startPyspnegoFixture(t, ctx)
	r := Request{Endpoint: endpoint, User: `EXAMPLE\alice`, Password: "test-secret"}
	send, receive, closeLanes, err := persistentLanes(r)(ctx)
	if err != nil {
		t.Fatalf("authenticate lanes: %v", err)
	}
	defer closeLanes()
	control := newTransport(r)
	s, err := startSessionLanes(ctx, Request{Endpoint: endpoint, Command: "receiver", PowerShell: true}, control, control, send, receive)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.close(cleanup)
	}()
	var stdout, stderr bytes.Buffer
	type outcome struct {
		rc  int
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		rc, err := s.receive(ctx, &stdout, &stderr)
		done <- outcome{rc, err}
	}()
	var want bytes.Buffer
	for i := 0; i < 5; i++ {
		// Let Receive poll while Send is active.
		time.Sleep(30 * time.Millisecond)
		chunk := []byte(fmt.Sprintf("chunk-%d\n", i))
		want.Write(chunk)
		if err := s.send(ctx, chunk, false); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := s.send(ctx, nil, true); err != nil {
		t.Fatalf("send EOF: %v", err)
	}
	got := <-done
	if got.err != nil || got.rc != 7 || stdout.String() != want.String() || stderr.String() != "err\n" {
		t.Fatalf("receive rc=%d err=%v stdout=%q stderr=%q", got.rc, got.err, stdout.String(), stderr.String())
	}
	if err := s.close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	// One entry per authenticated connection: Create, Command and Delete
	// on three short-lived ones, six Sends on one lane and at least one
	// timed-out Receive plus the final one on the other.
	calls := pyspnegoStats(t, ctx, endpoint)
	sort.Ints(calls)
	if len(calls) != 5 || calls[0] != 1 || calls[1] != 1 || calls[2] != 1 || calls[3] != 6 && calls[4] != 6 || calls[3]+calls[4] < 6+2 {
		t.Fatalf("SOAP calls per authenticated connection = %v", calls)
	}
}
