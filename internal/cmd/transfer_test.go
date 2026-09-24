package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lavr/winsh/internal/remote"
)

func transferDeps() Deps {
	return Deps{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard,
		Getenv: func(name string) string {
			if name == "WINRM_PASSWORD" {
				return "test-secret"
			}
			return ""
		}}
}

func TestTransferParse(t *testing.T) {
	for _, tt := range []struct {
		name              string
		args              []string
		wantErr           bool
		direction         remote.TransferDirection
		local, remotePath string
		force             bool
	}{
		{"upload", []string{"upload", "server.example.com", "--user", "alice", "--", "-local", `C:\Temp\dest.bin`}, false, remote.Upload, "-local", `C:\Temp\dest.bin`, false},
		{"download force", []string{"download", "server.example.com", "--user", "alice", "--force", "--", `C:\Temp\source.bin`, "-local"}, false, remote.Download, "-local", `C:\Temp\source.bin`, true},
		{"missing separator", []string{"upload", "server.example.com", "--user", "alice", "a", "b"}, true, "", "", "", false},
		{"one operand", []string{"upload", "server.example.com", "--user", "alice", "--", "a"}, true, "", "", "", false},
		{"three operands", []string{"upload", "server.example.com", "--user", "alice", "--", "a", "b", "c"}, true, "", "", "", false},
		{"stdin source", []string{"upload", "server.example.com", "--user", "alice", "--", "-", `C:\Temp\dest.bin`}, true, "", "", "", false},
		{"duplicate force", []string{"upload", "server.example.com", "--user", "alice", "--force", "--force", "--", "a", "b"}, true, "", "", "", false},
		{"codepage", []string{"upload", "server.example.com", "--user", "alice", "--codepage", "866", "--", "a", "b"}, true, "", "", "", false},
		{"script", []string{"upload", "server.example.com", "--user", "alice", "-f", "script.ps1", "--", "a", "b"}, true, "", "", "", false},
		{"password flag", []string{"upload", "server.example.com", "--user", "alice", "--password", "test-secret", "--", "a", "b"}, true, "", "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, req, err := parseTransfer(tt.args, transferDeps())
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v", err)
			}
			if err == nil && (req.Direction != tt.direction || req.LocalPath != tt.local || req.RemotePath != tt.remotePath || req.Force != tt.force) {
				t.Fatalf("request=%+v", req)
			}
		})
	}
}

func TestTransferTimeoutPrecedence(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := "current_context: lab\ncontexts:\n  lab:\n    host: lab\n    credentials: account\nhosts:\n  lab:\n    endpoint: http://server.example.com:5985/wsman\ncredentials:\n  account:\n    user: alice\n    password: literal:test-secret\ndefaults:\n  timeout: 60s\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args []string
		want time.Duration
	}{
		{"upload default", []string{"upload", "server.example.com", "--user", "alice", "--", "a", `C:\Temp\b`}, 30 * time.Minute},
		{"download default", []string{"download", "server.example.com", "--user", "alice", "--", `C:\Temp\b`, "a"}, 30 * time.Minute},
		{"upload yaml", []string{"upload", "--config", configPath, "--", "a", `C:\Temp\b`}, time.Minute},
		{"download cli", []string{"download", "--config", configPath, "--timeout", "2m", "--", `C:\Temp\b`, "a"}, 2 * time.Minute},
		{"run default", []string{"run", "server.example.com", "--user", "alice", "--", "hostname"}, time.Minute},
		{"ps yaml", []string{"ps", "--config", configPath, "--", "hostname"}, time.Minute},
		{"run cli", []string{"run", "--config", configPath, "--timeout", "2m", "--", "hostname"}, 2 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := transferDeps()
			d.Transfer = func(ctx context.Context, _ remote.TransferRequest, _ func(int64)) (remote.TransferResult, error) {
				checkDeadline(t, ctx, tt.want)
				return remote.TransferResult{Committed: true, SHA256: "abc"}, nil
			}
			d.Execute = func(ctx context.Context, _ remote.Request, _, _ io.Writer) (int, error) {
				checkDeadline(t, ctx, tt.want)
				return 0, nil
			}
			if rc := Run(t.Context(), tt.args, d); rc != 0 {
				t.Fatalf("rc=%d", rc)
			}
		})
	}
}

func checkDeadline(t *testing.T, ctx context.Context, want time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("missing deadline")
	}
	delta := time.Until(deadline)
	if delta < want-time.Second || delta > want {
		t.Fatalf("deadline=%v, want=%v", delta, want)
	}
}

func TestTransferErrorMapping(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		result  remote.TransferResult
		rc      int
		message string
	}{
		{"unknown cancel", &remote.FinalizationUnknownError{Cause: context.Canceled}, remote.TransferResult{}, 204, "finalization outcome unknown"},
		{"timeout", context.DeadlineExceeded, remote.TransferResult{}, 203, "timeout"},
		{"io", errors.New("test-secret payload-marker"), remote.TransferResult{}, 202, "transfer failed"},
		{"remote exit", &remote.RemoteExitError{Code: 17}, remote.TransferResult{}, 17, "remote command exited"},
		{"cleanup after commit", errors.New("cleanup failed"), remote.TransferResult{Committed: true, Bytes: 5, SHA256: "abc"}, 202, "cleanup"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			d := transferDeps()
			d.Stdout = &out
			d.Stderr = &errout
			calls := 0
			d.Transfer = func(context.Context, remote.TransferRequest, func(int64)) (remote.TransferResult, error) {
				calls++
				return tt.result, tt.err
			}
			rc := Run(t.Context(), []string{"upload", "server.example.com", "--user", "alice", "-vv", "--", "source.bin", `C:\Temp\dest.bin`}, d)
			if rc != tt.rc || calls != 1 || out.Len() != 0 || !strings.Contains(errout.String(), tt.message) || strings.Contains(errout.String(), "test-secret") || strings.Contains(errout.String(), "payload-marker") {
				t.Fatalf("rc=%d calls=%d out=%q err=%q", rc, calls, out.String(), errout.String())
			}
		})
	}
}

func TestTransferPasswordStdinAndProgress(t *testing.T) {
	var out, errout bytes.Buffer
	d := transferDeps()
	d.Stdin = strings.NewReader("test-secret\n")
	d.Stdout, d.Stderr = &out, &errout
	d.Getenv = func(name string) string {
		if name == "WINRM_PASSWORD" {
			t.Fatal("environment password read")
		}
		return ""
	}
	d.Transfer = func(_ context.Context, req remote.TransferRequest, progress func(int64)) (remote.TransferResult, error) {
		if req.Connection.Password != "test-secret" || req.Direction != remote.Download {
			t.Fatalf("request=%+v", req)
		}
		for i := int64(1); i <= 100; i++ {
			progress(i)
		}
		return remote.TransferResult{Committed: true, Bytes: 100, SHA256: "abc"}, nil
	}
	rc := Run(t.Context(), []string{"download", "server.example.com", "--user", "alice", "--password-stdin", "--", `C:\Temp\file.bin`, "out.bin"}, d)
	if rc != 0 || out.String() != "download 100 bytes SHA-256 abc\n" || strings.Count(errout.String(), " bytes\n") != 1 || !strings.Contains(errout.String(), "100 bytes total") {
		t.Fatalf("rc=%d out=%q err=%q", rc, out.String(), errout.String())
	}
}
