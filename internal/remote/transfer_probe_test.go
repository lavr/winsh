//go:build integration

// Probe WinRS streaming and filesystem commit behavior on a real WinRM
// endpoint. The probe is gated on WINSH_TEST_* (see TestLiveWindows) and
// produces the parameters that the implementations in later tasks depend on:
// receiver/sender wire shape, sharing semantics, atomic-rename primitive,
// and the effective envelope size. Output is intentionally verbose so the
// validation record can quote it.
//
// Probe scripts use $env:TEMP exclusively and a per-run GUID directory;
// nothing under user-named paths is touched.
package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	winrm "github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// liveCreds returns the WINSH_TEST_* values, skipping the test if any is
// missing. TargetHost is allowed to be empty for HTTP-only endpoints.
func liveCreds(t *testing.T) (endpoint, user, password, targetHost string) {
	t.Helper()
	endpoint = os.Getenv("WINSH_TEST_ENDPOINT")
	user = os.Getenv("WINSH_TEST_USER")
	password = os.Getenv("WINSH_TEST_PASSWORD")
	targetHost = os.Getenv("WINSH_TEST_TARGET_HOST")
	if endpoint == "" || user == "" || password == "" {
		t.Skip("set WINSH_TEST_ENDPOINT, WINSH_TEST_USER, WINSH_TEST_PASSWORD for live probe")
	}
	e, err := Endpoint("", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return e, user, password, targetHost
}

// runRemote runs a PowerShell snippet via the existing Run path. The snippet
// must fit within the 8000-character limit and produce no secret data on
// either stream. Output is captured to out/err buffers.
func runRemote(t *testing.T, ctx context.Context, endpoint, user, password, targetHost, script string) (string, string, int) {
	t.Helper()
	req := Request{Endpoint: endpoint, TargetHost: targetHost, User: user, Password: password, Command: script, PowerShell: true}
	var out, errBuf bytes.Buffer
	rc, err := Run(ctx, req, &out, &errBuf)
	if err != nil {
		t.Fatalf("remote %q: %v\nstdout=%q\nstderr=%q", strings.SplitN(script, "\n", 2)[0], err, out.String(), errBuf.String())
	}
	return out.String(), errBuf.String(), rc
}

// runStreaming opens a shell, executes the given PowerShell command, sends
// each chunk via SendInput (without EOF), sends EOF, then drains Receive
// until the command exits. Returns stdout, stderr, exit code, error. Mirrors
// run() in runner.go but defers stdin close so the receiver sees our data
// before EOF.
//
// The endpoint is contacted once per SOAP exchange; chunks therefore produce
// distinct Send requests, which is what later tasks need to exercise.
func runStreaming(ctx context.Context, endpoint, user, password, targetHost, command string, chunks [][]byte) (string, string, int, error) {
	r := Request{Endpoint: endpoint, TargetHost: targetHost, User: user, Password: password, Command: command, PowerShell: true}
	encoded, err := Command(r.Command, r.PowerShell)
	if err != nil {
		return "", "", 0, err
	}
	// Same CDATA escape as runner.go: literal "]]>" must not close the node.
	encoded = strings.ReplaceAll(encoded, "]]>", "]]]]><![CDATA[>")
	params := winrm.NewParameters("PT30S", "en-US", 153600)
	p := newTransport(r)
	send := func(ctx context.Context, m *soap.SoapMessage) (response, error) {
		defer m.Free()
		body, err := p.post(ctx, m.String())
		if err != nil {
			return response{}, err
		}
		return parseResponse(body)
	}
	opened, err := send(ctx, winrm.NewOpenShellRequest(r.Endpoint, params))
	if err != nil {
		return "", "", 0, err
	}
	shellID := opened.Body.Shell.ID
	if opened.Header.Action != wsTransfer+"CreateResponse" || !validID(shellID) {
		return "", "", 0, errors.New("invalid WinRM shell response")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		m := winrm.NewDeleteShellRequest(r.Endpoint, shellID, params)
		defer m.Free()
		_, _ = p.post(cleanup, m.String())
	}()
	started, err := send(ctx, winrm.NewExecuteCommandRequest(r.Endpoint, shellID, encoded, nil, params))
	if err != nil {
		return "", "", 0, err
	}
	commandID := started.Body.Command.ID
	if started.Header.Action != wsShell+"CommandResponse" || !validID(commandID) {
		return "", "", 0, errors.New("invalid WinRM command response")
	}
	for _, chunk := range chunks {
		if _, err := send(ctx, winrm.NewSendInputRequest(r.Endpoint, shellID, commandID, chunk, false, params)); err != nil {
			return "", "", 0, err
		}
	}
	if _, err := send(ctx, winrm.NewSendInputRequest(r.Endpoint, shellID, commandID, nil, true, params)); err != nil {
		return "", "", 0, err
	}
	var out, errBuf bytes.Buffer
	for {
		if err := ctx.Err(); err != nil {
			return "", "", 0, err
		}
		received, err := send(ctx, winrm.NewGetOutputRequest(r.Endpoint, shellID, commandID, "stdout stderr", params))
		if errors.Is(err, errOperationTimeout) {
			continue
		}
		if err != nil {
			return "", "", 0, err
		}
		done, rc, err := received.receive(&out, &errBuf)
		if err != nil {
			return "", "", 0, err
		}
		if done {
			return out.String(), errBuf.String(), rc, nil
		}
	}
}

// probeSetup creates a random directory under $env:TEMP and records host
// facts needed by the validation document. The directory is removed on
// test cleanup.
func probeSetup(t *testing.T, endpoint, user, password, targetHost string) string {
	t.Helper()
	snippet := "$d = Join-Path $env:TEMP ('winsh-probe-' + [guid]::NewGuid().ToString('N')); " +
		"New-Item -ItemType Directory -Path $d | Out-Null; " +
		"$d"
	out, _, rc := runRemote(t, t.Context(), endpoint, user, password, targetHost, snippet)
	if rc != 0 || strings.TrimSpace(out) == "" {
		t.Fatalf("create probe dir: rc=%d out=%q", rc, out)
	}
	dir := strings.TrimSpace(out)
	t.Cleanup(func() {
		cleanup := fmt.Sprintf("if (Test-Path -LiteralPath %q) { Remove-Item -LiteralPath %q -Recurse -Force }", dir, dir)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		runRemote(t, ctx, endpoint, user, password, targetHost, cleanup)
	})

	// Record environment facts. Strip any path-like text by truncating at the
	// first newline; values are short scalars, not secrets.
	for _, q := range []struct{ name, body string }{
		{"os", "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption"},
		{"os-version", "[System.Environment]::OSVersion.Version.ToString()"},
		{"powershell", "$PSVersionTable.PSVersion.ToString()"},
		{"filesystem", "(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FileSystem"},
		{"temp", "$env:TEMP"},
	} {
		out, _, _ := runRemote(t, t.Context(), endpoint, user, password, targetHost, q.body)
		t.Logf("probe-fact %s=%s", q.name, strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	}
	t.Logf("probe-fact envelope-bytes=153600")
	return dir
}

// receiverScript is the PowerShell receiver from the brief. It reads
// Base64-encoded lines from stdin until EOF, decodes each, accumulates
// bytes, and prints the count in invariant culture.
const receiverScript = "$ErrorActionPreference = 'Stop'; " +
	"$n = [long]0; " +
	"while ($null -ne ($line = [Console]::In.ReadLine())) { " +
	"  $chunk = [Convert]::FromBase64String($line); " +
	"  $n += $chunk.Length " +
	"}; " +
	"[Console]::Out.WriteLine($n.ToString([Globalization.CultureInfo]::InvariantCulture))"

// TestLiveTransferProbe runs the protocol probes against a configured
// endpoint. It exercises the WSMan Send/Receive/Command round-trip directly
// (not via Run), probes sharing and atomic-rename primitives, and records
// the observed envelope and protocol behavior. Each subtest is independent.
func TestLiveTransferProbe(t *testing.T) {
	endpoint, user, password, targetHost := liveCreds(t)
	dir := probeSetup(t, endpoint, user, password, targetHost)

	t.Run("ReceiverCountFromBase64Lines", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		// AAEC -> {0x00,0x01,0x02}, /w== -> {0xFF}
		// Sent in one chunk and across two chunks to verify framing.
		lines := [][]byte{
			[]byte("AAEC\r\n/w==\r\n"),
			[]byte("AAEC\r\n"),
			[]byte("/w==\r\n"),
		}
		var out, errBuf string
		var rc int
		var err error
		out, errBuf, rc, err = runStreaming(ctx, endpoint, user, password, targetHost, receiverScript, lines)
		if err != nil {
			t.Fatalf("receiver: %v\nstdout=%q\nstderr=%q", err, out, errBuf)
		}
		if rc != 0 {
			t.Fatalf("receiver exit %d stdout=%q stderr=%q", rc, out, errBuf)
		}
		got := strings.TrimSpace(out)
		if got != "8" {
			t.Fatalf("receiver counted %q, want 8 (3+1+3+1)", got)
		}
	})

	t.Run("ReceiverEmptyInput", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		out, errBuf, rc, err := runStreaming(ctx, endpoint, user, password, targetHost, receiverScript, nil)
		if err != nil {
			t.Fatalf("receiver empty: %v\nstdout=%q\nstderr=%q", err, out, errBuf)
		}
		if rc != 0 {
			t.Fatalf("receiver empty exit %d", rc)
		}
		if got := strings.TrimSpace(out); got != "0" {
			t.Fatalf("receiver empty counted %q, want 0", got)
		}
	})

	t.Run("ReceiverReceivesLinesAcrossMultipleSends", func(t *testing.T) {
		// Verify that a single Base64 line split across two SendInput requests
		// reassembles correctly on the receiver (no \r\n in the middle). This
		// matters because chunkSize must respect line framing.
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		lines := [][]byte{
			[]byte("AAEC"),             // half of line 1
			[]byte("/w==\r\n"),         // rest of line 1 + CRLF
			[]byte("AAEC\r\n/w==\r\n"), // full lines 2 and 3
		}
		out, errBuf, rc, err := runStreaming(ctx, endpoint, user, password, targetHost, receiverScript, lines)
		if err != nil {
			t.Fatalf("split line: %v\nstdout=%q\nstderr=%q", err, out, errBuf)
		}
		if rc != 0 {
			t.Fatalf("split line exit %d", rc)
		}
		if got := strings.TrimSpace(out); got != "8" {
			t.Fatalf("split line counted %q, want 8", got)
		}
	})

	t.Run("SenderStdoutStderrSeparation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		script := "[Console]::Out.WriteLine('winsh-data-line'); " +
			"[Console]::Error.WriteLine('winsh-meta-line'); " +
			"exit 7"
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		rc, err := Run(ctx, Request{Endpoint: endpoint, TargetHost: targetHost, User: user, Password: password, Command: script, PowerShell: true}, stdout, stderr)
		if err != nil {
			t.Fatalf("sender run: %v", err)
		}
		if rc != 7 {
			t.Fatalf("sender exit %d, want 7", rc)
		}
		if !strings.Contains(stdout.String(), "winsh-data-line") {
			t.Errorf("stdout missing data line: %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "winsh-meta-line") {
			t.Errorf("stderr missing meta line: %q", stderr.String())
		}
		if strings.Contains(stdout.String(), "winsh-meta-line") {
			t.Errorf("stderr leaked into stdout: %q", stdout.String())
		}
		if strings.Contains(stderr.String(), "winsh-data-line") {
			t.Errorf("stdout leaked into stderr: %q", stderr.String())
		}
	})

	t.Run("SharingReadBlocksWriteFromOtherProcess", func(t *testing.T) {
		// Create a small fixture file in the probe dir.
		fixture := path.Join(dir, "share.txt")
		runRemote(t, t.Context(), endpoint, user, password, targetHost,
			fmt.Sprintf("'hold' | Set-Content -LiteralPath %q -NoNewline", fixture))

		// Holder: opens with Read+FileShare.Read, signals readiness, blocks on
		// a "done" flag, then exits cleanly.
		ready := fixture + ".ready"
		done := fixture + ".done"
		holderScript := fmt.Sprintf(
			"$ErrorActionPreference = 'Stop'; "+
				"$h = [IO.File]::Open(%q, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read); "+
				"try { 'ready' | Set-Content -LiteralPath %q -NoNewline; "+
				"  while (-not (Test-Path -LiteralPath %q)) { Start-Sleep -Milliseconds 100 } "+
				"  'OK: held Read/Read' } finally { $h.Close() }",
			fixture, ready, done)

		// Writer: tries to open with Write+FileShare.None, expects sharing
		// violation, then signals done.
		writerScript := fmt.Sprintf(
			"$ErrorActionPreference = 'Stop'; "+
				"try { $h = [IO.File]::Open(%q, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None); "+
				"  'FAIL: opened with Write/None'; $h.Close(); exit 2 } "+
				"catch [IO.IOException] { 'OK: Write/None refused: ' + $_.Exception.Message; "+
				"  New-Item -ItemType File -Path %q -Force | Out-Null; exit 0 }",
			fixture, done)

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		defer cancel()

		holderCtx, holderCancel := context.WithTimeout(ctx, 3*time.Minute)
		holderDone := make(chan struct{})
		var holderOut, holderErr bytes.Buffer
		go func() {
			defer close(holderDone)
			defer holderCancel()
			_, _ = Run(holderCtx, Request{Endpoint: endpoint, TargetHost: targetHost, User: user, Password: password, Command: holderScript, PowerShell: true}, &holderOut, &holderErr)
		}()

		// Wait for the holder to signal readiness, then start the writer.
		deadline := time.Now().Add(30 * time.Second)
		for {
			readyCheck, _, _ := runRemote(t, ctx, endpoint, user, password, targetHost,
				fmt.Sprintf("if (Test-Path -LiteralPath %q) { 'yes' } else { 'no' }", ready))
			if !strings.Contains(readyCheck, "yes") {
				if time.Now().After(deadline) {
					t.Fatalf("holder did not signal readiness: holderOut=%q holderErr=%q", holderOut.String(), holderErr.String())
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			break
		}

		wOut, wErr, wRc := runRemote(t, ctx, endpoint, user, password, targetHost, writerScript)
		if wRc != 0 {
			t.Fatalf("writer exit %d stderr=%q", wRc, wErr)
		}
		if !strings.Contains(wOut, "OK: Write/None refused") {
			t.Fatalf("writer was not refused: %q", wOut)
		}

		select {
		case <-holderDone:
		case <-time.After(30 * time.Second):
			t.Fatalf("holder did not exit after writer signal: holderOut=%q holderErr=%q", holderOut.String(), holderErr.String())
		}
		if !strings.Contains(holderOut.String(), "OK: held Read/Read") {
			t.Fatalf("holder output missing OK: %q", holderOut.String())
		}
	})

	t.Run("MoveFileExWNoReplaceAndReplace", func(t *testing.T) {
		// Add-Type with an embedded C# snippet. The verbatim string contains
		// no single quotes, so single-quote PowerShell literal is safe.
		addType := "Add-Type -Namespace W -Name K -MemberDefinition '[DllImport(\"kernel32.dll\", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool MoveFileExW(string s, string d, uint f);' -ErrorAction Stop; "
		// Setup for case 1: src exists, dst does NOT exist.
		mkSrc := fmt.Sprintf("'new' | Set-Content -LiteralPath %q -NoNewline; ", path.Join(dir, "src.txt"))
		rmDst := fmt.Sprintf("if (Test-Path -LiteralPath %q) { Remove-Item -LiteralPath %q -Force -ErrorAction SilentlyContinue }; ", path.Join(dir, "dst.txt"), path.Join(dir, "dst.txt"))
		// Case 1: dst absent, MoveFileExW with flags=0 must succeed and the
		// source must be gone.
		case1 := fmt.Sprintf(
			"$ok = [W.K]::MoveFileExW(%q, %q, 0); "+
				"if (-not $ok) { 'FAIL: refused le=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { "+
				"  if ((Test-Path -LiteralPath %q) -and -not (Test-Path -LiteralPath %q)) { 'OK: moved no-replace' } else { 'FAIL: src still present or dst missing' } }",
			path.Join(dir, "src.txt"), path.Join(dir, "dst.txt"),
			path.Join(dir, "dst.txt"), path.Join(dir, "src.txt"))
		// Setup for cases 2 and 3: rebuild distinct src and dst, both present.
		redo := fmt.Sprintf("'second-new' | Set-Content -LiteralPath %q -NoNewline; 'second-old' | Set-Content -LiteralPath %q -NoNewline; ",
			path.Join(dir, "src2.txt"), path.Join(dir, "dst2.txt"))
		// Case 2: dst present, flags=0 must refuse (no-replace).
		case2 := fmt.Sprintf(
			"$ok = [W.K]::MoveFileExW(%q, %q, 0); "+
				"if ($ok) { 'FAIL: replaced without flag' } else { 'OK: refused no-replace le=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() }",
			path.Join(dir, "src2.txt"), path.Join(dir, "dst2.txt"))
		// Case 3: dst present, flags=MOVEFILE_REPLACE_EXISTING (0x1) must
		// succeed and the destination must contain the source bytes.
		case3 := fmt.Sprintf(
			"$ok = [W.K]::MoveFileExW(%q, %q, 1); "+
				"if (-not $ok) { 'FAIL: replace le=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { "+
				"  $c = Get-Content -LiteralPath %q -Raw; if ($c -eq 'second-new') { 'OK: replaced existing' } else { 'FAIL: content=' + $c } }",
			path.Join(dir, "src2.txt"), path.Join(dir, "dst2.txt"), path.Join(dir, "dst2.txt"))

		script := addType + mkSrc + rmDst + case1 + "; " + redo + case2 + "; " + case3
		out, errBuf, rc := runRemote(t, t.Context(), endpoint, user, password, targetHost, script)
		if rc != 0 {
			t.Fatalf("MoveFileExW script exit %d stdout=%q stderr=%q", rc, out, errBuf)
		}
		for _, want := range []string{"OK: moved no-replace", "OK: refused no-replace", "OK: replaced existing"} {
			if !strings.Contains(out, want) {
				t.Fatalf("MoveFileExW output missing %q: %q", want, out)
			}
		}
		t.Logf("probe-fact movefileexw-result=%s", strings.ReplaceAll(strings.TrimSpace(out), "\n", " | "))
	})
}

// no package-level state; readiness polling uses a local variable.
