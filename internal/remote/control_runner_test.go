package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type controlPostFunc func(context.Context, string) (string, error)

func (f controlPostFunc) Post(ctx context.Context, body string) (string, error) {
	return f(ctx, body)
}

func TestRunWithPostersPyspnegoInterop(t *testing.T) {
	if os.Getenv("WINSH_TEST_PYSPNEGO") != "1" {
		t.Skip("set WINSH_TEST_PYSPNEGO=1 after installing pyspnego")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	endpoint := startPyspnegoFixture(t, ctx)
	command, cleanup, closeBoth, err := NewPersistentPosters(ctx, Request{Endpoint: endpoint, User: `EXAMPLE\alice`, Password: "test-secret"})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	defer closeBoth()
	for i := 0; i < 2; i++ {
		var stdout, stderr bytes.Buffer
		rc, err := RunWithPosters(ctx, Request{Endpoint: endpoint, Command: "echo hi"}, &stdout, &stderr, command, cleanup)
		if err != nil || rc != 7 || stdout.String() != "ok\n" || stderr.String() != "err\n" {
			t.Fatalf("command %d: rc=%d err=%v out=%q errout=%q", i, rc, err, stdout.String(), stderr.String())
		}
	}
	if calls := pyspnegoStats(t, ctx, endpoint); !reflect.DeepEqual(calls, []int{0, 12}) {
		t.Fatalf("expected one command connection with 12 SOAP calls and untouched cleanup connection; got %v", calls)
	}
}

func TestRunWithPostersDistinctShellPerCommand(t *testing.T) {
	var actions []string
	commandNumber := 0
	command := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		shellID := "shell-" + strconv.Itoa(commandNumber)
		commandID := "command-" + strconv.Itoa(commandNumber)
		switch {
		case strings.Contains(body, transferURI+"Create"):
			commandNumber++
			actions = append(actions, "create")
			id := "shell-" + strconv.Itoa(commandNumber)
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>`+id+`</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			if !strings.Contains(body, shellID) {
				t.Errorf("Command did not use %s", shellID)
			}
			actions = append(actions, "command")
			id := "command-" + strconv.Itoa(commandNumber)
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>`+id+`</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(body, shellURI+"Send"):
			if !strings.Contains(body, shellID) || !strings.Contains(body, commandID) {
				t.Errorf("Send did not use %s and %s", shellID, commandID)
			}
			actions = append(actions, "send")
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(body, shellURI+"Receive"):
			if !strings.Contains(body, shellID) || !strings.Contains(body, commandID) {
				t.Errorf("Receive did not use %s and %s", shellID, commandID)
			}
			actions = append(actions, "receive")
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">b2sK</rsp:Stream><rsp:Stream Name="stderr">ZXJyCg==</rsp:Stream><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>7</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(body, shellURI+"Signal"):
			if !strings.Contains(body, shellID) || !strings.Contains(body, commandID) {
				t.Errorf("Signal did not use %s and %s", shellID, commandID)
			}
			actions = append(actions, "signal")
			return envelope(shellURI+"SignalResponse", ""), nil
		case strings.Contains(body, transferURI+"Delete"):
			if !strings.Contains(body, shellID) {
				t.Errorf("Delete did not use %s", shellID)
			}
			actions = append(actions, "delete")
			return envelope(transferURI+"DeleteResponse", ""), nil
		default:
			return "", errors.New("unexpected SOAP action")
		}
	})
	cleanup := controlPostFunc(func(context.Context, string) (string, error) {
		t.Fatal("healthy command used cleanup lane")
		return "", nil
	})
	for i := 0; i < 2; i++ {
		var stdout, stderr bytes.Buffer
		rc, err := RunWithPosters(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo hi"}, &stdout, &stderr, command, cleanup)
		if err != nil || rc != 7 || stdout.String() != "ok\n" || stderr.String() != "err\n" {
			t.Fatalf("command %d: rc=%d err=%v out=%q errout=%q", i, rc, err, stdout.String(), stderr.String())
		}
	}
	want := []string{"create", "command", "send", "receive", "signal", "delete", "create", "command", "send", "receive", "signal", "delete"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("SOAP actions = %v, want %v", actions, want)
	}
}

func TestRunWithPostersCreateResponseLost(t *testing.T) {
	command := controlPostFunc(func(context.Context, string) (string, error) {
		return "", errors.New("lost Shell Create response")
	})
	cleanup := controlPostFunc(func(context.Context, string) (string, error) {
		t.Fatal("cannot clean a Shell without its ID")
		return "", nil
	})
	_, err := RunWithPosters(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, command, cleanup)
	if !errors.Is(err, ErrRemoteStateUnknown) {
		t.Fatalf("lost Shell ID did not report unknown remote state: %v", err)
	}
}

func TestRunWithPostersCancellationUsesCleanupLane(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var cleaned []string
	command := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		switch {
		case strings.Contains(body, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(body, shellURI+"Send"):
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(body, shellURI+"Receive"):
			cancel()
			return "", ctx.Err()
		default:
			t.Fatalf("command lane used for cleanup: %q", body)
			return "", nil
		}
	})
	cleanup := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		if ctx.Err() != nil {
			t.Fatal("cleanup context already canceled")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("cleanup has no deadline")
		}
		switch {
		case strings.Contains(body, shellURI+"Signal"):
			cleaned = append(cleaned, "signal")
			return envelope(shellURI+"SignalResponse", ""), nil
		case strings.Contains(body, transferURI+"Delete"):
			cleaned = append(cleaned, "delete")
			return envelope(transferURI+"DeleteResponse", ""), nil
		default:
			return "", errors.New("unexpected cleanup action")
		}
	})
	_, err := RunWithPosters(ctx, Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, command, cleanup)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(cleaned, []string{"signal", "delete"}) {
		t.Fatalf("cancel=%v cleanup=%v", err, cleaned)
	}
}

func TestRunWithPostersCreateOnlyCleanup(t *testing.T) {
	var cleaned []string
	command := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		switch {
		case strings.Contains(body, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			return "", errors.New("lost Command response")
		default:
			return "", errors.New("unexpected command lane action")
		}
	})
	cleanup := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		if strings.Contains(body, shellURI+"Signal") {
			t.Fatal("signaled command with unknown ID")
		}
		if !strings.Contains(body, transferURI+"Delete") {
			t.Fatal("expected Shell Delete")
		}
		cleaned = append(cleaned, "delete")
		return envelope(transferURI+"DeleteResponse", ""), nil
	})
	_, err := RunWithPosters(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, command, cleanup)
	if err == nil || !reflect.DeepEqual(cleaned, []string{"delete"}) {
		t.Fatalf("err=%v cleanup=%v", err, cleaned)
	}
}

func TestRunWithPostersUnknownRemoteState(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := controlPostFunc(func(ctx context.Context, body string) (string, error) {
		switch {
		case strings.Contains(body, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(body, shellURI+"Send"):
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(body, shellURI+"Receive"):
			cancel()
			return "", ctx.Err()
		default:
			return "", errors.New("unexpected command lane action")
		}
	})
	cleanup := controlPostFunc(func(context.Context, string) (string, error) {
		return "", errors.New("private server details")
	})
	_, err := RunWithPosters(ctx, Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, command, cleanup)
	if !errors.Is(err, ErrRemoteStateUnknown) || strings.Contains(err.Error(), "private server details") {
		t.Fatalf("cleanup failure was not fixed and typed: %v", err)
	}
}
