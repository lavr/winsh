package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadRecordRejectsHiddenTrailingObject(t *testing.T) {
	body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `"}`
	body += strings.Repeat(" ", 4097-len(body)) + `{}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("accepted oversized record with hidden second JSON object")
	}
}
func TestCopyBase64LinesRejectsOversizeTerminatedLine(t *testing.T) {
	var b bytes.Buffer
	if _, err := copyBase64Lines(&b, strings.NewReader("AAAAAAAA\r\n"), 4); err == nil {
		t.Fatal("accepted 8-char line with maxLine=4")
	}
}

type zeroProgressWriter struct{ calls int }

func (w *zeroProgressWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return 0, io.ErrShortWrite
	}
	return 0, errors.New("test stops repeated write")
}
func TestWriteAllStopsOnZeroProgressShortWrite(t *testing.T) {
	w := new(zeroProgressWriter)
	_ = writeAll(w, []byte{1})
	if w.calls != 1 {
		t.Fatal("retries a zero-progress io.ErrShortWrite; a persistent writer error would spin forever")
	}
}
func TestRemoteStageParentPreservesDriveRoot(t *testing.T) {
	p, err := remoteStageParent(`C:\file.bin`)
	if err != nil || p != `C:\` {
		t.Fatalf("got parent %q err=%v, want drive root", p, err)
	}
}

type blockedOutputWriter struct{ entered, release chan struct{} }

func (w *blockedOutputWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}
func TestSessionCloseHonorsBudgetWithBlockedWriter(t *testing.T) {
	w := &blockedOutputWriter{make(chan struct{}), make(chan struct{})}
	s, err := startSession(t.Context(), Request{Endpoint: "http://example.com:5985/wsman", Command: "echo"}, postFunc(func(ctx context.Context, b string) (string, error) {
		switch {
		case strings.Contains(b, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>s1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(b, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>c1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(b, shellURI+"Receive"):
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">eA==</rsp:Stream><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(b, transferURI+"Delete"):
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
		}
		return "", errors.New("unexpected request")
	}))
	if err != nil {
		t.Fatal(err)
	}
	recvDone := make(chan struct{})
	go func() { defer close(recvDone); s.receive(t.Context(), w, io.Discard) }()
	<-w.entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	closeErr := s.close(ctx)
	elapsed := time.Since(start)
	close(w.release)
	<-recvDone
	if !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Errorf("close error = %v, want deadline exceeded", closeErr)
	}
	if elapsed > time.Second {
		t.Fatalf("20ms cleanup budget took %s", elapsed)
	}
}

func TestSessionReceiveOperationTimeout(t *testing.T) {
	p := postFunc(func(ctx context.Context, body string) (string, error) {
		if !strings.Contains(body, "PT30S") {
			t.Error("SOAP receive timeout must leave headroom below HTTP's 35s receive header timeout")
		}
		switch {
		case strings.Contains(body, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>s1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>c1</rsp:CommandId></rsp:CommandResponse>`), nil
		default:
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
	})
	s, err := startSession(t.Context(), Request{Endpoint: "http://example.com:5985/wsman", Command: "echo"}, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := s.close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseUnblocksOutputPipe(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	entered := make(chan struct{})
	s, err := startSession(t.Context(), Request{Endpoint: "http://example.com:5985/wsman", Command: "echo"}, postFunc(func(ctx context.Context, b string) (string, error) {
		switch {
		case strings.Contains(b, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>s1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(b, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>c1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(b, shellURI+"Receive"):
			close(entered)
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">eA==</rsp:Stream><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		default:
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan struct{})
	go func() { defer close(received); s.receive(t.Context(), writer, io.Discard) }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err = s.close(ctx)
	select {
	case <-s.recvDone:
	default:
		t.Error("receive worker still running after close")
	}
	writer.Close()
	<-received
	if err != nil {
		t.Fatal(err)
	}
}
