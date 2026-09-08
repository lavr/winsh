package remote

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"
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
