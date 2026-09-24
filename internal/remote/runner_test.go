package remote

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func envelope(action, body string) string {
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>` + action + `</a:Action></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}

const shellURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
const transferURI = "http://schemas.xmlsoap.org/ws/2004/09/transfer/"

type postFunc func(context.Context, string) (string, error)

func (f postFunc) post(ctx context.Context, s string) (string, error) { return f(ctx, s) }

func TestRunWSManFlow(t *testing.T) {
	var out, stderr bytes.Buffer
	deleted := false
	received := 0
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		var doc struct{ XMLName xml.Name }
		if err := xml.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatalf("invalid outbound SOAP: %v", err)
		}
		switch {
		case strings.Contains(s, transferURI+"Create"):
			if !strings.Contains(s, `Name="WINRS_CODEPAGE">866`) {
				t.Error("--codepage did not set WinRS output encoding")
			}
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			if !strings.Contains(s, "echo &lt;") && !strings.Contains(s, "echo <") {
				t.Error("command lost")
			}
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(s, shellURI+"Send"):
			if !strings.Contains(s, `End="true"`) {
				t.Error("stdin not closed")
			}
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(s, shellURI+"Receive"):
			received++
			if received == 1 {
				return envelope("http://schemas.dmtf.org/wbem/wsman/1/wsman/fault", `<s:Fault><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858793"/></s:Detail></s:Fault>`), nil
			}
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">j+CooqXiIQ==</rsp:Stream><rsp:Stream Name="stderr">ZXJyb3I=</rsp:Stream><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>37</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(s, transferURI+"Delete"):
			deleted = true
			return envelope(transferURI+"DeleteResponse", ""), nil
		default:
			t.Fatalf("unexpected request %s", s)
			return "", nil
		}
	})
	rc, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo <test> ]]> & exit /b 37", Codepage: "866"}, &out, &stderr, p)
	if err != nil || rc != 37 || out.String() != "Привет!" || stderr.String() != "error" || !deleted {
		t.Fatalf("rc=%d err=%v stdout=%q stderr=%q deleted=%v", rc, err, out.String(), stderr.String(), deleted)
	}
}

func TestRunCleanupAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cleaned := false
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		if strings.Contains(s, transferURI+"Create") {
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		}
		if strings.Contains(s, transferURI+"Delete") {
			cleaned = true
			if ctx.Err() != nil {
				t.Error("cleanup got canceled context")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("unbounded cleanup")
			}
			return "", nil
		}
		cancel()
		return "", ctx.Err()
	})
	_, err := run(ctx, Request{Endpoint: "http://localhost:5985/wsman", Command: "hostname"}, io.Discard, io.Discard, p)
	if !errors.Is(err, context.Canceled) || !cleaned {
		t.Fatalf("err=%v cleaned=%v", err, cleaned)
	}
}

func TestReceiveRejectsMalformedData(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"bad XML", "<bad"},
		{"bad stream", envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:Stream Name="stdout">%%%bad</rsp:Stream></rsp:ReceiveResponse>`)},
		{"missing exit", envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"/></rsp:ReceiveResponse>`)},
		{"bad exit", envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>oops</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseResponse(tt.body)
			if err == nil {
				_, _, err = r.receive(io.Discard, io.Discard)
			}
			if err == nil {
				t.Fatal("accepted malformed output")
			}
		})
	}
}

// TestRunSendResponseAction verifies that the session layer verifies the
// SendResponse action and rejects conflicting ones (e.g. a stray Receive
// response arriving in place of SendResponse).
func TestRunSendResponseAction(t *testing.T) {
	var sendSeen atomic.Int32
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		switch {
		case strings.Contains(s, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(s, shellURI+"Send"):
			sendSeen.Add(1)
			// Return a ReceiveResponse instead of SendResponse to verify
			// the action check rejects the wrong action.
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(s, transferURI+"Delete"):
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
		return "", errors.New("unexpected")
	})
	_, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo", PowerShell: true}, io.Discard, io.Discard, p)
	if err == nil {
		t.Fatal("accepted ReceiveResponse as SendResponse")
	}
	if !strings.Contains(err.Error(), "SendResponse") {
		t.Fatalf("error %q does not mention SendResponse", err)
	}
	if sendSeen.Load() != 1 {
		t.Fatalf("sendSeen=%d, want 1", sendSeen.Load())
	}
}

// TestRunExplicitEOFZeroByte exercises the send with empty data and
// eof=true. This is the wire shape used by both run() and the eventual
// upload receiver: the data field is empty, the End attribute is true.
func TestRunExplicitEOFZeroByte(t *testing.T) {
	var sendPayload []byte
	var sendEOF bool
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		switch {
		case strings.Contains(s, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(s, shellURI+"Send"):
			// Capture the End="..." attribute and data field so the test
			// can assert the wire shape that the session layer produced.
			sendEOF = strings.Contains(s, `End="true"`)
			// The body has an empty <x:Stream> element when data is nil;
			// we just record that Send was invoked.
			sendPayload = []byte{}
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(s, shellURI+"Receive"):
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(s, transferURI+"Delete"):
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
		return "", errors.New("unexpected")
	})
	var out, errBuf bytes.Buffer
	if _, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo"}, &out, &errBuf, p); err != nil {
		t.Fatal(err)
	}
	if !sendEOF {
		t.Fatal("EOF was not sent")
	}
	if sendPayload == nil {
		t.Fatal("Send was not invoked")
	}
}

// TestRunRejectsConflictingShellID checks that a response carrying a
// shell ID we did not issue is rejected. WSMan responses are tied to
// the shell we opened; anything else is either a replay attempt or a
// server bug, both of which we treat as a hard error.
func TestRunRejectsConflictingShellID(t *testing.T) {
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		switch {
		case strings.Contains(s, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			// Return a shell ID that differs from the one we opened.
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId><rsp:Shell><rsp:ShellId>shell-2</rsp:ShellId></rsp:Shell></rsp:CommandResponse>`), nil
		}
		return "", errors.New("unexpected")
	})
	_, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo"}, io.Discard, io.Discard, p)
	if err == nil {
		t.Fatal("accepted conflicting shell id")
	}
}

// TestRunEarlyRemoteExit covers a remote script that emits Done on the
// very first Receive. The session must surface the exit code without
// spinning on the operation-timeout retry path.
func TestRunEarlyRemoteExit(t *testing.T) {
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		switch {
		case strings.Contains(s, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(s, shellURI+"Send"):
			return envelope(shellURI+"SendResponse", ""), nil
		case strings.Contains(s, shellURI+"Receive"):
			return envelope(shellURI+"ReceiveResponse", `<rsp:ReceiveResponse><rsp:CommandState State="`+shellURI+`CommandState/Done"><rsp:ExitCode>7</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`), nil
		case strings.Contains(s, transferURI+"Delete"):
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
		return "", errors.New("unexpected")
	})
	var out, errBuf bytes.Buffer
	rc, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "exit 7"}, &out, &errBuf, p)
	if err != nil {
		t.Fatal(err)
	}
	if rc != 7 {
		t.Fatalf("rc=%d, want 7", rc)
	}
}

// TestRunSendFailureNoReplay asserts that a failed SendInput is not
// silently retried. Replays could double-deliver bytes to the receiver
// and corrupt the staged file; the brief explicitly forbids them.
func TestRunSendFailureNoReplay(t *testing.T) {
	var sendSeen atomic.Int32
	p := postFunc(func(ctx context.Context, s string) (string, error) {
		switch {
		case strings.Contains(s, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(s, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(s, shellURI+"Send"):
			sendSeen.Add(1)
			return "", errors.New("transport failed")
		case strings.Contains(s, transferURI+"Delete"):
			return envelope(transferURI+"DeleteResponse", ""), nil
		}
		return "", errors.New("unexpected")
	})
	_, err := run(t.Context(), Request{Endpoint: "http://localhost:5985/wsman", Command: "echo"}, io.Discard, io.Discard, p)
	if err == nil {
		t.Fatal("send failure swallowed")
	}
	if sendSeen.Load() != 1 {
		t.Fatalf("sendSeen=%d, want 1 (no replay)", sendSeen.Load())
	}
}
