package remote

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestSessionSendOverlapWithReceive exercises the case where the fake
// poster blocks Send until the receive loop has polled Receive at least
// once. Both must complete; neither must leak a goroutine.
func TestSessionSendOverlapWithReceive(t *testing.T) {
	receivePolled := make(chan struct{}, 1)

	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Send"):
				// Wait until the receive loop has polled at least once.
				select {
				case <-receivePolled:
				case <-ctx.Done():
					return "", ctx.Err()
				}
				return envelope(shellURI+"SendResponse", ""), nil
			case strings.Contains(s, shellURI+"Receive"):
				select {
				case receivePolled <- struct{}{}:
				default:
				}
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.close(ctx)
	})

	before := runtime.NumGoroutine()
	sendDone := make(chan error, 1)
	go func() { sendDone <- s.send(t.Context(), []byte("data"), false) }()

	var stdout, stderr bytes.Buffer
	rc, err := s.receive(t.Context(), &stdout, &stderr)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("send: %v", err)
	}

	// Allow a brief window for any straggler goroutines (the receive loop's
	// deferred close, the send helper goroutine) to settle, then check.
	time.Sleep(50 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > before+1 {
		t.Errorf("goroutine count grew from %d to %d", before, got)
	}
}

// TestSessionReceiveExitWhileSendBlocked verifies that closing the
// session unblocks an in-flight SendInput whose poster never responds.
// This is the "inverse failure" the plan calls out: Receive exits while
// Send is stuck.
func TestSessionReceiveExitWhileSendBlocked(t *testing.T) {
	sendEntered := make(chan struct{})
	releaseSend := make(chan struct{})

	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Send"):
				close(sendEntered)
				// Either the test releases the barrier or close() cancels
				// the in-flight post via the session's lifecycle signal;
				// either way we unblock and return.
				select {
				case <-releaseSend:
					return envelope(shellURI+"SendResponse", ""), nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			case strings.Contains(s, shellURI+"Receive"):
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Pending"></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	before := runtime.NumGoroutine()
	sendDone := make(chan error, 1)
	go func() { sendDone <- s.send(t.Context(), []byte("data"), false) }()

	<-sendEntered

	// Cancel receive with a short ctx; receive returns ctx.Err().
	rctx, rcancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	var stdout, stderr bytes.Buffer
	if _, err := s.receive(rctx, &stdout, &stderr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("receive err=%v, want DeadlineExceeded", err)
	}
	rcancel()

	// Close with a fresh budget. This cancels the receive loop and the
	// lifecycle signal should unblock Send's stuck post().
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}
	// After close, release the fake poster so the lingering goroutine in
	// the test harness does not leak.
	close(releaseSend)

	select {
	case err := <-sendDone:
		if err == nil {
			t.Fatal("send succeeded despite close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("send did not return after close")
	}

	time.Sleep(50 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Errorf("goroutine count grew from %d to %d (close leaked workers)", before, got)
	}
}

// TestSessionCancellationJoinsWorkers covers the case where the caller's
// context is cancelled mid-flight. Both the receive loop and any
// in-flight SendInput must observe the cancellation; recvDone must
// close within the budget.
func TestSessionCancellationJoinsWorkers(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Send"), strings.Contains(s, shellURI+"Receive"):
				<-ctx.Done()
				return "", ctx.Err()
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		var stdout, stderr bytes.Buffer
		_, _ = s.receive(ctx, &stdout, &stderr)
	}()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("receive did not return after caller cancellation")
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestSessionSendAfterCloseRejected verifies that send() called after
// close() returns promptly with an error instead of issuing a fresh
// SOAP request against a deleted shell.
func TestSessionSendAfterCloseRejected(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Receive"):
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := s.send(t.Context(), []byte("data"), false); err == nil {
		t.Fatal("send after close accepted")
	}
}

// TestSessionSendMessageAfterCloseRejected is the raw escape hatch's
// equivalent of TestSessionSendAfterCloseRejected.
func TestSessionSendMessageAfterCloseRejected(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := s.sendMessage([]byte("<x/>")); err == nil {
		t.Fatal("sendMessage after close accepted")
	}
}

// TestSessionDoubleCloseIsSafe: close() must be idempotent. Two close
// calls within their respective budgets both return nil.
func TestSessionDoubleCloseIsSafe(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	ctx1, c1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer c1()
	if err := s.close(ctx1); err != nil {
		t.Fatal(err)
	}
	ctx2, c2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer c2()
	if err := s.close(ctx2); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// TestSessionReceiveBeforeOutput: receive() blocks until receiveLoop
// has actually polled. With a fake that returns Pending on first
// Receive and Done on the second, receive returns the exit code.
func TestSessionReceiveBeforeOutput(t *testing.T) {
	calls := 0
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Receive"):
				calls++
				if calls == 1 {
					return envelope(shellURI+"ReceiveResponse",
						`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Pending"></rsp:CommandState></rsp:ReceiveResponse>`), nil
				}
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>11</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.close(ctx)
	})

	var stdout, stderr bytes.Buffer
	rc, err := s.receive(t.Context(), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if rc != 11 {
		t.Fatalf("rc=%d, want 11", rc)
	}
	if calls < 2 {
		t.Fatalf("receive polled only %d times", calls)
	}
}

// TestSessionReceiveAfterCloseReturnsRealResult covers the result race:
// receive() called after close() must observe the exit code the receive
// loop published, not a zero torn read of recvExit / recvErr.
func TestSessionReceiveAfterCloseReturnsRealResult(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Receive"):
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>42</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	rc, err := s.receive(t.Context(), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if rc != 42 {
		t.Fatalf("first receive rc=%d, want 42", rc)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Re-receive must observe the same real exit code; without the
	// wait-for-recvDone fix this used to return 0 from a torn read.
	rc2, err := s.receive(t.Context(), &stdout, &stderr)
	if err != nil {
		t.Fatalf("post-close receive: %v", err)
	}
	if rc2 != 42 {
		t.Fatalf("post-close receive rc=%d, want 42 (result race)", rc2)
	}
}

// TestSessionSimultaneousClose: two goroutines call close() at the
// same time. Only one wins the CompareAndSwap; the other waits for
// recvDone. Neither leaks.
func TestSessionSimultaneousClose(t *testing.T) {
	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Receive"):
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	_, _ = s.receive(t.Context(), &stdout, &stderr)

	close1Done := make(chan error, 1)
	close2Done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		close1Done <- s.close(ctx)
	}()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		close2Done <- s.close(ctx)
	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-close1Done:
			if err != nil {
				t.Errorf("close1: %v", err)
			}
		case err := <-close2Done:
			if err != nil {
				t.Errorf("close2: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("simultaneous close deadlocked")
		}
	}
}

// TestSessionSendBlockedByReceiveGoroutineWait verifies that a Send
// queued in another goroutine is unblocked by close() even when the
// receive loop is still busy. close() must signal lifecycleDone before
// acquiring sendMu so the blocked post can return.
func TestSessionSendBlockedByReceiveGoroutineWait(t *testing.T) {
	sendEntered := make(chan struct{})

	s, err := startSession(t.Context(),
		Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true},
		postFunc(func(ctx context.Context, s string) (string, error) {
			switch {
			case strings.Contains(s, transferURI+"Create"):
				return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
			case strings.Contains(s, shellURI+"Command"):
				return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
			case strings.Contains(s, shellURI+"Send"):
				close(sendEntered)
				<-ctx.Done()
				return "", ctx.Err()
			case strings.Contains(s, shellURI+"Receive"):
				return envelope(shellURI+"ReceiveResponse",
					`<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Pending"></rsp:CommandState></rsp:ReceiveResponse>`), nil
			case strings.Contains(s, transferURI+"Delete"):
				return envelope(transferURI+"DeleteResponse", ""), nil
			}
			return "", errors.New("unexpected action")
		}))
	if err != nil {
		t.Fatal(err)
	}

	sendDone := make(chan error, 1)
	go func() { sendDone <- s.send(t.Context(), []byte("data"), false) }()
	<-sendEntered

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := s.close(closeCtx); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-sendDone:
		if err == nil {
			t.Fatal("send succeeded despite close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("send did not return after close")
	}
}
