package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInvokeStreamsAndExitCode(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		defer server.Close()
		kind, payload, err := readFrame(server)
		if err != nil || kind != frameRequest || !bytes.Contains(payload, []byte("hostname")) {
			finished <- ErrProtocol
			return
		}
		for _, frame := range []struct {
			kind frameType
			data string
		}{{frameStdout, "out-1"}, {frameStderr, "err-1"}, {frameStdout, "out-2"}} {
			if err := writeFrame(server, frame.kind, []byte(frame.data)); err != nil {
				finished <- err
				return
			}
		}
		finished <- writeJSONFrame(server, frameResult, Result{ExitCode: 37})
	}()
	var stdout, stderr bytes.Buffer
	result, err := invokeConn(t.Context(), client, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, &stdout, &stderr)
	if err != nil || result.ExitCode != 37 || stdout.String() != "out-1out-2" || stderr.String() != "err-1" {
		t.Fatalf("result=%+v err=%v stdout=%q stderr=%q", result, err, stdout.String(), stderr.String())
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("local output broken") }

func TestInvokeBrokenOutputWriterClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	closed := make(chan error, 1)
	go func() {
		_, _, _ = readFrame(server)
		if err := writeFrame(server, frameStdout, []byte("x")); err != nil {
			closed <- err
			return
		}
		_, _, err := readFrame(server)
		closed <- err
	}()
	_, err := invokeConn(context.Background(), client, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, brokenWriter{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "local output broken") {
		t.Fatalf("writer failure lost: %v", err)
	}
	if err := <-closed; !errors.Is(err, io.EOF) {
		t.Fatalf("client left server connection open: %v", err)
	}
}

func TestInvokeUnixSocketAndFixedError(t *testing.T) {
	dir := shortControlDir(t)
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, _, err := readFrame(conn); err != nil {
			done <- err
			return
		}
		done <- writeFrame(conn, frameError, []byte(CategoryQueueFull))
	}()
	_, err = Invoke(t.Context(), socket, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, io.Discard, io.Discard)
	var category CategoryError
	if !errors.As(err, &category) || category.Category != CategoryQueueFull {
		t.Fatalf("fixed server error = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInvokeCanceledCommandReportsUnknownRemoteState(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_, _, _ = readFrame(server)
		cancel()
	}()
	_, err := invokeConn(ctx, client, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, io.Discard, io.Discard)
	var category CategoryError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &category) || category.Category != CategoryRemoteStateUnknown {
		t.Fatalf("canceled submitted command did not report uncertainty: %v", err)
	}
}

type blockedWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w blockedWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(p), nil
}

func TestInvokeBlockedOutputReturnsAtDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	writer := blockedWriter{started: make(chan struct{}), release: make(chan struct{})}
	defer close(writer.release)
	go func() {
		_, _, _ = readFrame(server)
		_ = writeFrame(server, frameStdout, []byte("x"))
	}()
	finished := make(chan error, 1)
	go func() {
		_, err := invokeConn(t.Context(), client, Call{Command: "hostname", Deadline: time.Now().Add(50 * time.Millisecond)}, writer, io.Discard)
		finished <- err
	}()
	<-writer.started
	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked output deadline = %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("client stayed blocked in output write after deadline")
	}
}

func TestInvokeLostReplyIsUncertain(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _, _ = readFrame(server)
		_ = server.Close()
	}()
	_, err := invokeConn(t.Context(), client, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, io.Discard, io.Discard)
	var category CategoryError
	if !errors.As(err, &category) || category.Category != CategoryRemoteStateUnknown {
		t.Fatalf("lost reply category = %v", err)
	}
}

type failedAfterWriteConn struct{ net.Conn }

func (c failedAfterWriteConn) Write(p []byte) (int, error) {
	n, _ := c.Conn.Write(p)
	return n, errors.New("write acknowledgment lost")
}

func TestInvokeAmbiguousRequestWriteIsUncertain(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _, _, _ = readFrame(server) }()
	_, err := invokeConn(t.Context(), failedAfterWriteConn{client}, Call{Command: "hostname", Deadline: time.Now().Add(time.Second)}, io.Discard, io.Discard)
	var category CategoryError
	if !errors.As(err, &category) || category.Category != CategoryRemoteStateUnknown {
		t.Fatalf("ambiguous request submission = %v", err)
	}
}
