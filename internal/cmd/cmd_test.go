package cmd

import (
	"bytes"
	"context"
	"errors"
	"github.com/lavr/winsh/internal/remote"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		args                  []string
		wantCommand, wantUser string
		rc                    int
	}{
		{"command", []string{"run", "server", "--user", "alice", "--domain", "EXAMPLE", "--", "echo", "--help", "-vv"}, "echo --help -vv", `EXAMPLE\alice`, 37},
		{"powershell", []string{"ps", "--endpoint", "http://localhost:5985/wsman", "--user", `EXAMPLE\alice`, "--", "Write-Output 'Привет'"}, "Write-Output 'Привет'", `EXAMPLE\alice`, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			calls := 0
			rc := Run(t.Context(), tt.args, Deps{Stdout: &out, Stderr: &errout, Stdin: strings.NewReader(""), Getenv: func(name string) string {
				if name == "WINRM_PASSWORD" {
					return "test-secret"
				}
				return ""
			}, Execute: func(ctx context.Context, r remote.Request, o, e io.Writer) (int, error) {
				calls++
				if r.Command != tt.wantCommand || r.User != tt.wantUser || r.Password != "test-secret" {
					t.Error("wrong request")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("no deadline")
				}
				io.WriteString(o, "output")
				io.WriteString(e, "diagnostic")
				return tt.rc, nil
			}})
			if rc != tt.rc || out.String() != "output" || errout.String() != "diagnostic" || calls != 1 {
				t.Fatalf("rc=%d stdout=%q stderr=%q calls=%d", rc, out.String(), errout.String(), calls)
			}
		})
	}
}

func TestRejectInvalidInputBeforeNetwork(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"password flag", []string{"run", "server", "--password", "test-secret", "--", "hostname"}},
		{"credentials in endpoint", []string{"run", "--endpoint", "http://a:test-secret@localhost", "--user", "a", "--", "hostname"}},
		{"missing separator", []string{"run", "server", "--user", "alice", "hostname"}},
		{"both password sources", []string{"run", "server", "--user", "alice", "--password-env", "PASS", "--password-stdin", "--", "hostname"}},
		{"invalid timeout", []string{"run", "server", "--user", "alice", "--timeout", "0s", "--", "hostname"}},
		{"unknown auth", []string{"run", "server", "--user", "alice", "--auth", "kerberos", "--", "hostname"}},
		{"conflicting domain", []string{"run", "server", "--user", `OTHER\alice`, "--domain", "EXAMPLE", "--", "hostname"}},
		{"unsupported codepage", []string{"run", "server", "--user", "alice", "--codepage", "test-secret", "--", "hostname"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var errout bytes.Buffer
			rc := Run(t.Context(), tt.args, Deps{Stdout: io.Discard, Stderr: &errout, Stdin: strings.NewReader(""), Getenv: func(name string) string {
				if name == "WINRM_PASSWORD" {
					return "test-secret"
				}
				return ""
			}, Execute: func(context.Context, remote.Request, io.Writer, io.Writer) (int, error) {
				t.Error("network called")
				return 0, nil
			}})
			if rc != 201 {
				t.Errorf("rc=%d stderr=%s", rc, errout.String())
			}
			if strings.Contains(errout.String(), "test-secret") {
				t.Error("secret echoed")
			}
		})
	}
}

func TestPasswordStdinAndScriptFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "script.ps1")
	if err := os.WriteFile(file, []byte("\xef\xbb\xbfWrite-Output 'file'"), 0600); err != nil {
		t.Fatal(err)
	}
	var errout bytes.Buffer
	rc := Run(t.Context(), []string{"ps", "server", "--user", "a", "--password-stdin", "-f", file}, Deps{Stdout: io.Discard, Stderr: &errout, Stdin: strings.NewReader(" test-secret \r\n"), Getenv: func(name string) string {
		if name == "WINRM_PASSWORD" {
			t.Error("read password environment despite stdin")
		}
		return ""
	}, Execute: func(_ context.Context, r remote.Request, _, _ io.Writer) (int, error) {
		if r.Password != " test-secret " || r.Command != "Write-Output 'file'" {
			t.Error("bad request")
		}
		return 0, nil
	}})
	if rc != 0 {
		t.Fatalf("%d %s", rc, errout.String())
	}
}

func TestLocalErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		rc   int
	}{{"network", errors.New("contains test-secret"), 202}, {"timeout", context.DeadlineExceeded, 203}, {"cancel", context.Canceled, 204}} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			rc := Run(context.Background(), []string{"run", "server", "--user", "alice", "--timeout", time.Second.String(), "--", "hostname"}, Deps{Stdout: io.Discard, Stderr: &output, Stdin: strings.NewReader(""), Getenv: func(name string) string {
				if name == "WINRM_PASSWORD" {
					return "test-secret"
				}
				return ""
			}, Execute: func(context.Context, remote.Request, io.Writer, io.Writer) (int, error) { return 0, tt.err }})
			if rc != tt.rc || strings.Contains(output.String(), "test-secret") {
				t.Errorf("rc=%d output=%q", rc, output.String())
			}
		})
	}
}
