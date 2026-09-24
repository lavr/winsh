package remote

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type downloadFake struct {
	mu           sync.Mutex
	commands     int
	id           string
	data, record string
	senderRC     int
	cleanupRC    int
}

func (f *downloadFake) post(_ context.Context, body string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(body, transferURI+"Create"):
		return envelope(transferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell</rsp:ShellId></rsp:Shell>`), nil
	case strings.Contains(body, shellURI+"Command"):
		f.commands++
		if f.commands == 2 {
			f.id = uploadIDFromCommand(body)
		}
		return envelope(shellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command</rsp:CommandId></rsp:CommandResponse>`), nil
	case strings.Contains(body, shellURI+"Send"):
		return envelope(shellURI+"SendResponse", ""), nil
	case strings.Contains(body, shellURI+"Receive"):
		out, rc := "", 0
		switch f.commands {
		case 1:
			out = `C:\Temp` + "\n"
		case 2:
			out, rc = f.data, f.senderRC
		case 3:
			out = strings.ReplaceAll(f.record, "placeholder", f.id)
		case 4:
			out = "OK: cleaned\n"
			rc = f.cleanupRC
		}
		return envelope(shellURI+"ReceiveResponse", fmt.Sprintf(`<rsp:ReceiveResponse><rsp:Stream Name="stdout">%s</rsp:Stream><rsp:CommandState State="%sCommandState/Done"><rsp:ExitCode>%d</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, base64.StdEncoding.EncodeToString([]byte(out)), shellURI, rc)), nil
	case strings.Contains(body, transferURI+"Delete"):
		return envelope(transferURI+"DeleteResponse", ""), nil
	}
	return "", fmt.Errorf("unexpected SOAP request")
}

func TestDownloadBinaryRoundTrip(t *testing.T) {
	data := []byte{0, 1, 2, 255, 0, 128}
	h := sha256.Sum256(data)
	sum := hex.EncodeToString(h[:])
	f := &downloadFake{data: base64.StdEncoding.EncodeToString(data) + "\r\n", record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":%d,"sha256":"%s"}`, len(data), sum)}
	dest := filepath.Join(t.TempDir(), "download.bin")
	r, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(data) || !r.Committed || r.Bytes != int64(len(data)) || r.SHA256 != sum {
		t.Fatalf("result=%+v err=%v bytes=%x", r, err, got)
	}
}

func TestDownloadPreservesExistingDestination(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "download.bin")
	if err := os.WriteFile(dest, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("new"))
	sum := hex.EncodeToString(h[:])
	f := &downloadFake{data: base64.StdEncoding.EncodeToString([]byte("new")) + "\r\n", record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":3,"sha256":"%s"}`, sum)}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("existing destination replaced")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "original" {
		t.Fatalf("destination changed: %q", got)
	}
}

func TestDownloadRejectsWrongControlID(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "download.bin")
	h := sha256.Sum256(nil)
	sum := hex.EncodeToString(h[:])
	f := &downloadFake{record: fmt.Sprintf(`{"version":1,"id":"wrong","bytes":0,"sha256":"%s"}`, sum)}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("wrong control ID accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("destination created on metadata mismatch")
	}
}

func TestDownloadRejectsMalformedBase64(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "download.bin")
	f := &downloadFake{data: "%%%\r\n"}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source.bin`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("malformed data accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("destination created on malformed data")
	}
}

func TestDownloadEmptyFile(t *testing.T) {
	h := sha256.Sum256(nil)
	f := &downloadFake{record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":0,"sha256":"%s"}`, hex.EncodeToString(h[:]))}
	dest := filepath.Join(t.TempDir(), "empty")
	r, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\empty`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err != nil || !r.Committed || r.Bytes != 0 {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Size() != 0 {
		t.Fatalf("info=%v err=%v", info, err)
	}
}

func TestDownloadForceReplacesExisting(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(dest, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	data := []byte("new")
	h := sha256.Sum256(data)
	f := &downloadFake{data: base64.StdEncoding.EncodeToString(data) + "\r\n", record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":3,"sha256":"%s"}`, hex.EncodeToString(h[:]))}
	r, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source`, Force: true, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	got, _ := os.ReadFile(dest)
	if err != nil || !r.Committed || string(got) != "new" {
		t.Fatalf("result=%+v err=%v bytes=%q", r, err, got)
	}
}

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "target")
	wrong := sha256.Sum256([]byte("wrong"))
	f := &downloadFake{data: base64.StdEncoding.EncodeToString([]byte("right")) + "\r\n", record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":5,"sha256":"%s"}`, hex.EncodeToString(wrong[:]))}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("destination created")
	}
}

func TestDownloadRejectsNonzeroSender(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "target")
	f := &downloadFake{senderRC: 7}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	var exit *RemoteExitError
	if !errors.As(err, &exit) || exit.Code != 7 {
		t.Fatalf("err=%v", err)
	}
}

func TestDownloadCleanupFailureKeepsCommittedResult(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "target")
	h := sha256.Sum256(nil)
	f := &downloadFake{record: fmt.Sprintf(`{"version":1,"id":"placeholder","bytes":0,"sha256":"%s"}`, hex.EncodeToString(h[:])), cleanupRC: 1}
	r, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: dest, RemotePath: `C:\Temp\source`, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(f.post))
	if err == nil || !r.Committed || len(r.Artifacts) != 1 {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestDownloadRejectsDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := download(t.Context(), TransferRequest{Direction: Download, LocalPath: link, RemotePath: `C:\Temp\source`, Force: true, Connection: Request{Endpoint: "http://example.com:5985/wsman"}}, nil, postFunc(func(context.Context, string) (string, error) {
		t.Error("network called")
		return "", errors.New("unexpected")
	}))
	if !IsTransferInputError(err) {
		t.Fatalf("err=%v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Fatalf("target changed: %q", got)
	}
}
