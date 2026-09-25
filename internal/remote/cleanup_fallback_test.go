package remote

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shellFake answers a completed command; Delete is handled by the caller.
func shellFake(t *testing.T, del func(context.Context) (string, error)) postFunc {
	return func(ctx context.Context, body string) (string, error) {
		switch soapAction(body) {
		case "Create":
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case "Command":
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case "Send":
			return envelope(shellURI+"SendResponse", ""), nil
		case "Receive":
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case "Delete":
			return del(ctx)
		}
		t.Errorf("unexpected action %s", soapAction(body))
		return "", errors.New("unexpected action")
	}
}

func deleted(context.Context) (string, error) {
	return envelope(transferURI+"DeleteResponse", ""), nil
}

func TestCloseSendsUnsentDeleteThroughFallback(t *testing.T) {
	var fallbackDeletes atomic.Int32
	lane := shellFake(t, func(context.Context) (string, error) {
		return "", unsent(errors.New("NTLM connection is closed"))
	})
	fallback := postFunc(func(ctx context.Context, body string) (string, error) {
		if soapAction(body) != "Delete" {
			t.Errorf("fallback carried %s", soapAction(body))
		}
		fallbackDeletes.Add(1)
		return deleted(ctx)
	})
	_, err := runWithCleanup(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, lane, lane, fallback)
	if err != nil || fallbackDeletes.Load() != 1 {
		t.Fatalf("err=%v fallback deletes=%d", err, fallbackDeletes.Load())
	}
}

func TestCloseNeverResendsDispatchedDelete(t *testing.T) {
	lane := shellFake(t, func(context.Context) (string, error) {
		return "", errors.New("WinRM SOAP exchange: connection reset")
	})
	fallback := postFunc(func(context.Context, string) (string, error) {
		t.Error("uncertain Delete was resent")
		return "", nil
	})
	_, err := runWithCleanup(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, lane, lane, fallback)
	if !errors.Is(err, ErrRemoteStateUnknown) && (err == nil || !strings.Contains(err.Error(), "shell cleanup failed")) {
		t.Fatalf("err=%v", err)
	}
}

func TestRunWithPostersCompletedCommandFallsBackForDelete(t *testing.T) {
	var fallbackDeletes atomic.Int32
	command := shellFake(t, func(context.Context) (string, error) {
		return "", unsent(errors.New("NTLM connection is closed"))
	})
	cleanup := controlPostFunc(func(context.Context, string) (string, error) {
		return "", unsent(errors.New("NTLM connection is closed"))
	})
	fallback := postFunc(func(ctx context.Context, body string) (string, error) {
		fallbackDeletes.Add(1)
		return deleted(ctx)
	})
	rc, runErr, cleanupErr := runWithPosters(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, controlPostFunc(command), cleanup, fallback)
	if rc != 0 || runErr != nil || cleanupErr != nil || fallbackDeletes.Load() != 1 {
		t.Fatalf("rc=%d runErr=%v cleanupErr=%v fallback deletes=%d", rc, runErr, cleanupErr, fallbackDeletes.Load())
	}
}

func TestCompletedCleanupErrorIsNotCommandTimeout(t *testing.T) {
	err := completedCleanupError(errors.Join(ErrRemoteStateUnknown, context.DeadlineExceeded))
	if errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrRemoteStateUnknown) || !strings.Contains(err.Error(), "remote command completed") {
		t.Fatalf("err=%v", err)
	}
	err = completedCleanupError(errors.Join(ErrCleanupFailed, context.DeadlineExceeded))
	if errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("err=%v", err)
	}
}

func TestCleanupRemoteStageReportsCloseFailure(t *testing.T) {
	lane := postFunc(func(ctx context.Context, body string) (string, error) {
		switch soapAction(body) {
		case "Receive":
			stdout := "T0s6IGNsZWFuZWQ=" // "OK: cleaned"
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">`+stdout+`</rsp:Stream><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case "Delete":
			return "", errors.New("WinRM SOAP exchange: connection reset")
		}
		return shellFake(t, deleted)(ctx, body)
	})
	err := cleanupRemoteStage(t.Context(), TransferRequest{Connection: Request{Endpoint: "http://localhost:5985/wsman"}}, `C:\Temp\.winsh-stage-1`, lane, nil)
	if err == nil || !strings.Contains(err.Error(), "close cleanup shell") {
		t.Fatalf("err=%v", err)
	}
}

func TestKeepLanesAliveStops(t *testing.T) {
	var beats atomic.Int32
	lane := &countingKeeper{beats: &beats}
	stop := keepLanesAlive(t.Context(), 5*time.Millisecond, lane)
	time.Sleep(30 * time.Millisecond)
	stop()
	after := beats.Load()
	time.Sleep(20 * time.Millisecond)
	if after == 0 || beats.Load() != after {
		t.Fatalf("beats before stop=%d after stop=%d", after, beats.Load())
	}
}

type countingKeeper struct{ beats *atomic.Int32 }

func (c *countingKeeper) Post(context.Context, string) (string, error) { return "", nil }
func (c *countingKeeper) KeepAlive(context.Context, time.Duration) error {
	c.beats.Add(1)
	return nil
}

func TestFailedCommandDeleteFallsBack(t *testing.T) {
	var fallbackDeletes atomic.Int32
	control := postFunc(func(ctx context.Context, body string) (string, error) {
		if soapAction(body) == "Command" {
			return "", errors.New("WinRM fault 2150858770")
		}
		return shellFake(t, deleted)(ctx, body)
	})
	cleanup := postFunc(func(context.Context, string) (string, error) {
		return "", unsent(errors.New("NTLM connection is closed"))
	})
	fallback := postFunc(func(ctx context.Context, body string) (string, error) {
		fallbackDeletes.Add(1)
		return deleted(ctx)
	})
	_, err := startSessionLanes(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, control, cleanup, control, control, fallback)
	if err == nil || errors.Is(err, ErrRemoteStateUnknown) || fallbackDeletes.Load() != 1 {
		t.Fatalf("err=%v fallback deletes=%d", err, fallbackDeletes.Load())
	}
}
