package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

// uploadFake wires two fake WinRM sessions (receiver + finalizer) into
// a single postFunc. Tests inject the per-session stdout payloads via
// the fields below.
type uploadFake struct {
	mu             sync.Mutex
	receiverStdout string
	receiverStderr string
	receiverRC     int
	receiverErr    error

	finalizerStdout string
	finalizerStderr string
	finalizerRC     int
	finalizerErr    error

	opens      int
	cmds       int
	sends      int
	receives   int
	deletes    int
	transferID string
}

var encodedCommandRE = regexp.MustCompile(`-EncodedCommand ([A-Za-z0-9+/=]+)`)
var transferIDRE = regexp.MustCompile(`\$id = \[Text.Encoding\]::Unicode.GetString\(\[Convert\]::FromBase64String\('([^']+)'\)\)`)

func uploadIDFromCommand(body string) string {
	outer := encodedCommandRE.FindStringSubmatch(body)
	if len(outer) != 2 {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(outer[1])
	if err != nil || len(data)%2 != 0 {
		return ""
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	inner := transferIDRE.FindStringSubmatch(string(utf16.Decode(units)))
	if len(inner) != 2 {
		return ""
	}
	data, err = base64.StdEncoding.DecodeString(inner[1])
	if err != nil || len(data)%2 != 0 {
		return ""
	}
	units = make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	return string(utf16.Decode(units))
}

func (f *uploadFake) post(_ context.Context, body string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(body, transferURI+"Create"):
		f.opens++
		return envelope(transferURI+"CreateResponse",
			fmt.Sprintf(`<rsp:Shell><rsp:ShellId>shell-%d</rsp:ShellId></rsp:Shell>`, f.opens)), nil
	case strings.Contains(body, shellURI+"Command"):
		f.cmds++
		if f.cmds == 1 {
			f.transferID = uploadIDFromCommand(body)
		}
		return envelope(shellURI+"CommandResponse",
			fmt.Sprintf(`<rsp:CommandResponse><rsp:CommandId>cmd-%d</rsp:CommandId></rsp:CommandResponse>`,
				f.opens)), nil
	case strings.Contains(body, shellURI+"Send"):
		f.sends++
		return envelope(shellURI+"SendResponse", ""), nil
	case strings.Contains(body, shellURI+"Receive"):
		f.receives++
		var stdout string
		var rc int
		var rerr error
		if f.opens == 1 {
			stdout, rc, rerr = f.receiverStdout, f.receiverRC, f.receiverErr
		} else {
			stdout, rc, rerr = f.finalizerStdout, f.finalizerRC, f.finalizerErr
		}
		if rerr != nil {
			return "", rerr
		}
		stdout = strings.ReplaceAll(stdout, "placeholder", f.transferID)
		if f.opens > 1 && stdout == "OK: committed" {
			stdout += ":" + f.transferID
		}
		stderrText := f.finalizerStderr
		if f.opens == 1 {
			stderrText = f.receiverStderr
		}
		stdoutEnc := base64.StdEncoding.EncodeToString([]byte(stdout))
		stderrEnc := base64.StdEncoding.EncodeToString([]byte(stderrText))
		return envelope(shellURI+"ReceiveResponse",
			fmt.Sprintf(`<rsp:ReceiveResponse><rsp:Stream Name="stdout">%s</rsp:Stream><rsp:Stream Name="stderr">%s</rsp:Stream><rsp:CommandState State="%sCommandState/Done"><rsp:ExitCode>%d</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`,
				stdoutEnc, stderrEnc, shellURI, rc)), nil
	case strings.Contains(body, transferURI+"Delete"):
		f.deletes++
		return envelope(transferURI+"DeleteResponse", ""), nil
	}
	return "", errors.New("unexpected action")
}

// uploadFixture builds a 96 KiB source file with a known SHA-256 and a
// transfer request that targets an arbitrary remote path. Tests use it
// to drive the upload pipeline through the fake poster.
func uploadFixture(t *testing.T) (TransferRequest, string, []byte, string) {
	t.Helper()
	src := make([]byte, 96*1024)
	for i := range src {
		src[i] = byte(i * 7)
	}
	path := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(path, src, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(src)
	sum := hex.EncodeToString(h[:])
	req := TransferRequest{
		Direction:  Upload,
		LocalPath:  path,
		RemotePath: `C:\Temp\dest.bin`,
		Connection: Request{Endpoint: "http://127.0.0.1:5985/wsman", PowerShell: true},
	}
	return req, path, src, sum
}

func TestUploadEndToEnd(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	f := &uploadFake{
		receiverStdout:  `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`,
		finalizerStdout: "OK: committed",
	}
	res, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !res.Committed {
		t.Fatal("not committed")
	}
	if res.Bytes != int64(len(srcData)) || res.SHA256 != sum {
		t.Fatalf("result mismatch: bytes=%d sha=%s", res.Bytes, res.SHA256)
	}
	if f.opens != 2 || f.cmds != 2 || f.sends == 0 || f.receives < 2 || f.deletes != 2 {
		t.Errorf("unexpected counts: open=%d cmd=%d send=%d recv=%d del=%d",
			f.opens, f.cmds, f.sends, f.receives, f.deletes)
	}
}

func TestUploadDrainsReceiveWhileSending(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	f := &uploadFake{receiverStdout: `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`, finalizerStdout: "OK: committed"}
	receiving := make(chan struct{})
	var once sync.Once
	p := postFunc(func(ctx context.Context, body string) (string, error) {
		if strings.Contains(body, shellURI+"Receive") {
			once.Do(func() { close(receiving) })
		}
		if strings.Contains(body, shellURI+"Send") {
			select {
			case <-receiving:
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
				return "", errors.New("Send began before Receive")
			}
		}
		return f.post(ctx, body)
	})
	result, err := upload(t.Context(), req, nil, p)
	if err != nil || !result.Committed {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestUploadRefusesExistingDestination(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	f := &uploadFake{
		receiverStdout:  `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`,
		finalizerStdout: "STAGE_HASH_MISMATCH",
		finalizerStderr: "STAGE_HASH_MISMATCH",
		finalizerRC:     3,
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("commit without --force accepted when destination exists")
	}
}

func TestUploadRejectsCountMismatch(t *testing.T) {
	req, _, _, sum := uploadFixture(t)
	// Receiver reports fewer bytes than we sent.
	f := &uploadFake{
		receiverStdout: `{"version":1,"id":"placeholder","bytes":1,"sha256":"` + sum + `"}`,
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("count mismatch accepted")
	}
	if !strings.Contains(err.Error(), "count mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUploadRejectsHashMismatch(t *testing.T) {
	req, _, srcData, _ := uploadFixture(t)
	other := sha256.Sum256([]byte("not the same"))
	wrongSum := hex.EncodeToString(other[:])
	f := &uploadFake{
		receiverStdout: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":%d,"sha256":"%s"}`,
			len(srcData), wrongSum),
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("hash mismatch accepted")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUploadRejectsIDMismatch(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	f := &uploadFake{
		receiverStdout: `{"version":1,"id":"wrong","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`,
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("id mismatch accepted")
	}
}

func TestUploadRejectsInvalidStageResult(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	f := &uploadFake{
		receiverStdout: `not valid json`,
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("malformed result accepted")
	}
}

func TestUploadSendFailureNoReplay(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	sends := 0
	p := postFunc(func(_ context.Context, body string) (string, error) {
		switch {
		case strings.Contains(body, transferURI+"Create"):
			return envelope(transferURI+"CreateResponse",
				`<rsp:Shell><rsp:ShellId>s</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, shellURI+"Command"):
			return envelope(shellURI+"CommandResponse",
				`<rsp:CommandResponse><rsp:CommandId>c</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(body, shellURI+"Send"):
			sends++
			return "", errors.New("transport failed")
		}
		return "", errors.New("unexpected")
	})
	_, err := upload(t.Context(), req, nil, p)
	if err == nil {
		t.Fatal("send failure swallowed")
	}
	if sends != 1 {
		t.Errorf("sends=%d, want 1 (no replay)", sends)
	}
}

func TestUploadSourceReadError(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	// Truncate the source so the second read fails with EOF after the
	// first successful chunk. The hash check rejects the mismatch.
	if err := os.Truncate(req.LocalPath, 1); err != nil {
		t.Fatal(err)
	}
	f := &uploadFake{
		receiverStdout: `{"version":1,"id":"placeholder","bytes":1,"sha256":"` + sha256HexOf([]byte{0}) + `"}`,
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("source truncation accepted")
	}
}

func TestUploadUnknownFinalizerOutcome(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	// Receiver returns a valid record; finalizer's Receive exits zero
	// but produces no "OK: committed" line. This is the "ack lost"
	// scenario: we cannot tell whether the commit happened.
	f := &uploadFake{
		receiverStdout:  `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`,
		finalizerStdout: "(no ack)",
	}
	_, err := upload(t.Context(), req, nil, postFunc(f.post))
	var final *FinalizationUnknownError
	if !errors.As(err, &final) {
		t.Fatalf("expected FinalizationUnknownError, got %T: %v", err, err)
	}
}

func TestUploadRejectsInvalidDirection(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	req.Direction = Download
	_, err := upload(t.Context(), req, nil, postFunc(func(_ context.Context, _ string) (string, error) {
		return "", errors.New("no calls expected")
	}))
	if err == nil {
		t.Fatal("wrong direction accepted")
	}
}

func TestUploadRejectsBadLocalPath(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	req.LocalPath = ""
	_, err := upload(t.Context(), req, nil, postFunc(func(_ context.Context, _ string) (string, error) {
		return "", errors.New("no calls expected")
	}))
	if !IsTransferInputError(err) {
		t.Fatalf("expected TransferInputError, got %v", err)
	}
}

func TestUploadRejectsBadRemotePath(t *testing.T) {
	req, _, _, _ := uploadFixture(t)
	req.RemotePath = "C:\\bad|path"
	_, err := upload(t.Context(), req, nil, postFunc(func(_ context.Context, _ string) (string, error) {
		return "", errors.New("no calls expected")
	}))
	if !IsTransferInputError(err) {
		t.Fatalf("expected TransferInputError, got %v", err)
	}
}

func TestUploadProgressIsMonotonic(t *testing.T) {
	req, _, _, sum := uploadFixture(t)
	var seen []int64
	var mu sync.Mutex
	progress := func(n int64) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, n)
	}
	f := &uploadFake{
		receiverStdout:  `{"version":1,"id":"placeholder","bytes":98304,"sha256":"` + sum + `"}`,
		finalizerStdout: "OK: committed",
	}
	res, err := upload(t.Context(), req, progress, postFunc(f.post))
	if err != nil || !res.Committed {
		t.Fatalf("upload failed: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("no progress callbacks")
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			t.Fatalf("non-monotonic progress: %v", seen)
		}
	}
	if seen[len(seen)-1] != res.Bytes {
		t.Fatalf("final progress %d != result bytes %d", seen[len(seen)-1], res.Bytes)
	}
}

func TestUploadCancelBeforeCommitIsKnownFailure(t *testing.T) {
	req, _, srcData, sum := uploadFixture(t)
	// Cancel immediately so the second session cannot establish.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f := &uploadFake{
		receiverStdout: `{"version":1,"id":"placeholder","bytes":` + fmt.Sprint(len(srcData)) + `,"sha256":"` + sum + `"}`,
	}
	_, err := upload(ctx, req, nil, postFunc(f.post))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %T: %v", err, err)
	}
}

// sha256HexOf is a tiny helper used by a couple of tests above.
func sha256HexOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// keep bytes imported if test-only references drift
var _ = bytes.Buffer{}
var _ = time.Second
