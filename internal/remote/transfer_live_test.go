//go:build integration

package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests use only WINSH_TEST_* and a unique directory below the remote
// account's temporary directory. No endpoint or credential is stored here.
func liveTransferSetup(t *testing.T) (Request, string) {
	t.Helper()
	endpoint, user, password, targetHost := liveCreds(t)
	connection := Request{Endpoint: endpoint, User: user, Password: password, TargetHost: targetHost}
	script := "$p = Join-Path $env:TEMP ('winsh-transfer-' + [guid]::NewGuid().ToString('N')); (New-Item -ItemType Directory -Path $p).FullName"
	out, _, rc := runRemote(t, t.Context(), endpoint, user, password, targetHost, script)
	if rc != 0 || strings.TrimSpace(out) == "" {
		t.Fatal("cannot create remote test directory")
	}
	dir := strings.TrimSpace(out)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		quoted := "'" + strings.ReplaceAll(dir, "'", "''") + "'"
		cleanup := "$ErrorActionPreference = 'Stop'; Remove-Item -LiteralPath " + quoted + " -Recurse -Force; if (Test-Path -LiteralPath " + quoted + ") { exit 1 }"
		_, _, rc := runRemote(t, ctx, endpoint, user, password, targetHost, cleanup)
		if rc != 0 {
			t.Error("remote test directory cleanup failed")
		}
	})
	return connection, dir
}

func fileHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func remoteHash(t *testing.T, connection Request, path string) string {
	t.Helper()
	quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	script := "(Get-FileHash -LiteralPath " + quoted + " -Algorithm SHA256).Hash.ToLowerInvariant()"
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	out, _, rc := runRemote(t, ctx, connection.Endpoint, connection.User, connection.Password, connection.TargetHost, script)
	if rc != 0 {
		t.Fatalf("remote hash exit %d", rc)
	}
	return strings.TrimSpace(out)
}

func TestLiveTransferRoundTrip(t *testing.T) {
	connection, dir := liveTransferSetup(t)
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"binary", []byte{0, 255, 1, 0, 2, 128, 10, 13}},
		{"unicode and spaces", []byte("unicode file content\x00")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			localDir := t.TempDir()
			localSource := filepath.Join(localDir, "source.bin")
			if err := os.WriteFile(localSource, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			name := tt.name + " 'юникод'.bin"
			remotePath := strings.TrimRight(dir, `\/`) + `\` + name
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()
			uploadReq := TransferRequest{Connection: connection, Direction: Upload, LocalPath: localSource, RemotePath: remotePath}
			result, err := Transfer(ctx, uploadReq, nil)
			if err != nil {
				t.Fatalf("upload: %v", errors.New(redactLive(err.Error(), connection.Password)))
			}
			want := fileHash(t, localSource)
			if !result.Committed || result.Bytes != int64(len(tt.data)) || result.SHA256 != want || remoteHash(t, connection, remotePath) != want {
				t.Fatalf("upload verification failed")
			}
			if _, err := Transfer(ctx, uploadReq, nil); err == nil {
				t.Fatal("upload without force replaced existing destination")
			}
			uploadReq.Force = true
			if result, err := Transfer(ctx, uploadReq, nil); err != nil || !result.Committed {
				t.Fatalf("force upload: %v", err)
			}
			localDest := filepath.Join(localDir, "download.bin")
			downloadReq := TransferRequest{Connection: connection, Direction: Download, LocalPath: localDest, RemotePath: remotePath}
			result, err = Transfer(ctx, downloadReq, nil)
			if err != nil {
				t.Fatalf("download: %v", errors.New(redactLive(err.Error(), connection.Password)))
			}
			if !result.Committed || result.Bytes != int64(len(tt.data)) || result.SHA256 != want || fileHash(t, localDest) != want {
				t.Fatal("download verification failed")
			}
			if _, err := Transfer(ctx, downloadReq, nil); err == nil {
				t.Fatal("download without force replaced existing destination")
			}
			downloadReq.Force = true
			if result, err := Transfer(ctx, downloadReq, nil); err != nil || !result.Committed {
				t.Fatalf("force download: %v", err)
			}
		})
	}
}

func redactLive(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[REDACTED]")
}

// Fault cases use callback and SOAP action barriers. They run only in the
// extended suite because each case opens several authenticated shells.
func TestLiveTransferFaults(t *testing.T) {
	if os.Getenv("WINSH_TEST_TRANSFER_LARGE") != "1" {
		t.Skip("set WINSH_TEST_TRANSFER_LARGE=1 for adversarial transfer checks")
	}
	connection, dir := liveTransferSetup(t)
	local := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(local, []byte("verified payload"), 0600); err != nil {
		t.Fatal(err)
	}
	want := fileHash(t, local)
	makeReq := func(name string) TransferRequest {
		return TransferRequest{Connection: connection, Direction: Upload, LocalPath: local, RemotePath: strings.TrimRight(dir, `\/`) + `\` + name}
	}
	remoteWrite := func(tb *testing.T, path string, data string) {
		tb.Helper()
		quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
		script := "[IO.File]::WriteAllBytes(" + quoted + ", [Text.Encoding]::UTF8.GetBytes('" + data + "'))"
		ctx, cancel := context.WithTimeout(tb.Context(), 30*time.Second)
		defer cancel()
		_, _, rc := runRemote(tb, ctx, connection.Endpoint, connection.User, connection.Password, connection.TargetHost, script)
		if rc != 0 {
			tb.Fatalf("remote write exit %d", rc)
		}
	}
	base := newTransport(connection)
	t.Run("cancel at sent chunk", func(t *testing.T) {
		req := makeReq("cancel.bin")
		ctx, cancel := context.WithCancel(t.Context())
		calls := 0
		_, err := transfer(ctx, req, func(int64) { calls++; cancel() }, base)
		if err == nil || calls != 1 {
			t.Fatalf("cancel: err=%v callbacks=%d", err, calls)
		}
		ctx2, stop := context.WithTimeout(t.Context(), time.Minute)
		defer stop()
		if result, err := Transfer(ctx2, req, nil); err != nil || !result.Committed {
			t.Fatalf("retry after cancel: %s", redactLive(fmt.Sprint(err), connection.Password))
		}
		if remoteHash(t, connection, req.RemotePath) != want {
			t.Fatal("retry hash mismatch")
		}
	})
	t.Run("source changed", func(t *testing.T) {
		req := makeReq("source-changed.bin")
		calls := 0
		_, err := transfer(t.Context(), req, func(int64) {
			calls++
			if calls == 1 {
				if e := os.WriteFile(local, []byte("changed payload"), 0600); e != nil {
					t.Fatal(e)
				}
			}
		}, base)
		if err == nil {
			t.Fatal("source mutation accepted")
		}
		if err := os.WriteFile(local, []byte("verified payload"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("competing destination", func(t *testing.T) {
		req := makeReq("compete.bin")
		commands := 0
		p := postFunc(func(ctx context.Context, body string) (string, error) {
			if strings.Contains(body, shellURI+"Command") {
				commands++
				if commands == 2 {
					remoteWrite(t, req.RemotePath, "competitor")
				}
			}
			return base.post(ctx, body)
		})
		_, err := transfer(t.Context(), req, nil, p)
		var exit *RemoteExitError
		if !errors.As(err, &exit) || commands < 2 {
			t.Fatalf("competition: err=%s commands=%d", redactLive(fmt.Sprint(err), connection.Password), commands)
		}
		if remoteHash(t, connection, req.RemotePath) == want {
			t.Fatal("competing destination overwritten")
		}
	})
	t.Run("lost finalizer reply", func(t *testing.T) {
		req := makeReq("lost-reply.bin")
		commands := 0
		dropped := false
		p := postFunc(func(ctx context.Context, body string) (string, error) {
			if strings.Contains(body, shellURI+"Command") {
				commands++
			}
			response, err := base.post(ctx, body)
			if commands == 2 && !dropped && strings.Contains(body, shellURI+"Receive") && strings.Contains(response, "CommandState/Done") {
				dropped = true
				return "", errors.New("injected response loss")
			}
			return response, err
		})
		_, err := transfer(t.Context(), req, nil, p)
		var unknown *FinalizationUnknownError
		if !errors.As(err, &unknown) || commands != 2 || !dropped {
			t.Fatalf("lost reply: err=%s commands=%d dropped=%t", redactLive(fmt.Sprint(err), connection.Password), commands, dropped)
		}
		if remoteHash(t, connection, req.RemotePath) != want {
			t.Fatal("commit not complete after dropped reply")
		}
		if _, err := Transfer(t.Context(), req, nil); err == nil {
			t.Fatal("retry without force replaced destination")
		}
	})
	t.Run("cleanup after commit", func(t *testing.T) {
		req := makeReq("cleanup-failure.bin")
		commands := 0
		failed := false
		p := postFunc(func(ctx context.Context, body string) (string, error) {
			if strings.Contains(body, shellURI+"Command") {
				commands++
			}
			if commands == 2 && !failed && strings.Contains(body, transferURI+"Delete") {
				failed = true
				return "", errors.New("injected cleanup failure")
			}
			return base.post(ctx, body)
		})
		result, err := transfer(t.Context(), req, nil, p)
		if !result.Committed || err == nil || !failed {
			t.Fatalf("cleanup: committed=%t err=%s failed=%t", result.Committed, redactLive(fmt.Sprint(err), connection.Password), failed)
		}
		if remoteHash(t, connection, req.RemotePath) != want {
			t.Fatal("cleanup changed committed file")
		}
	})
	t.Run("missing destination parents", func(t *testing.T) {
		uploadReq := makeReq(`missing\file.bin`)
		if result, err := Transfer(t.Context(), uploadReq, nil); err == nil || result.Committed {
			t.Fatal("upload accepted a missing remote destination parent")
		}
		downloadReq := TransferRequest{Connection: connection, Direction: Download,
			RemotePath: strings.TrimRight(dir, `\/`) + `\cancel.bin`,
			LocalPath:  filepath.Join(t.TempDir(), "missing", "download.bin")}
		if result, err := Transfer(t.Context(), downloadReq, nil); err == nil || result.Committed {
			t.Fatal("download accepted a missing local destination parent")
		}
	})
}

func TestLiveTransferLarge(t *testing.T) {
	if os.Getenv("WINSH_TEST_TRANSFER_LARGE") != "1" {
		t.Skip("set WINSH_TEST_TRANSFER_LARGE=1 for large transfer measurement")
	}
	connection, dir := liveTransferSetup(t)
	for _, size := range []int64{100 << 20, 200 << 20} {
		if !t.Run(fmt.Sprintf("%dMiB", size>>20), func(t *testing.T) {
			localDir := t.TempDir()
			source := filepath.Join(localDir, "source.bin")
			f, err := os.Create(source)
			if err != nil {
				t.Fatal(err)
			}
			pattern := make([]byte, 32<<10)
			for i := range pattern {
				pattern[i] = byte(i * 31)
			}
			for written := int64(0); written < size; written += int64(len(pattern)) {
				if _, err := f.Write(pattern); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			want := fileHash(t, source)
			remotePath := strings.TrimRight(dir, `\/`) + fmt.Sprintf(`\large-%d.bin`, size)
			for _, direction := range []TransferDirection{Upload, Download} {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
				localPath := source
				if direction == Download {
					localPath = filepath.Join(localDir, "download.bin")
				}
				start := time.Now()
				var progressed atomic.Int64
				result, err := Transfer(ctx, TransferRequest{Connection: connection, Direction: direction, LocalPath: localPath, RemotePath: remotePath}, func(n int64) { progressed.Store(n) })
				cancel()
				if err != nil {
					t.Fatalf("%s after %d bytes in %s: %s", direction, progressed.Load(), time.Since(start), redactLive(err.Error(), connection.Password))
				}
				elapsed := time.Since(start)
				if !result.Committed || result.Bytes != size || result.SHA256 != want {
					t.Fatalf("%s verification failed", direction)
				}
				if direction == Download && fileHash(t, localPath) != want {
					t.Fatal("download hash mismatch")
				}
				if direction == Upload && remoteHash(t, connection, remotePath) != want {
					t.Fatal("remote hash mismatch")
				}
				t.Logf("%s bytes=%d elapsed=%s throughput=%.0f bytes/s", direction, size, elapsed, float64(size)/elapsed.Seconds())
			}
		}) {
			return
		}
	}
}
