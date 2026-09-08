package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lavr/winsh/internal/remote"
)

func TestConfiguredExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `current_context: test
hosts:
  windows:
    endpoint: http://localhost:15985/wsman
credentials:
  account:
    user: base64:YWxpY2U=
    password: plain-test-secret
    domain: EXAMPLE
contexts:
  test:
    host: windows
    credentials: account
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, before := range []bool{true, false} {
		args := []string{"ps", "--config", path, "--", "--context untouched"}
		if before {
			args = []string{"--config", path, "ps", "--", "--context untouched"}
		}
		var stderr strings.Builder
		called := false
		rc := Run(t.Context(), args, Deps{Stdout: io.Discard, Stderr: &stderr, Getenv: func(string) string { return "" }, Execute: func(_ context.Context, r remote.Request, _, _ io.Writer) (int, error) {
			called = true
			if r.User != `EXAMPLE\alice` || r.Password != "plain-test-secret" || r.Endpoint != "http://localhost:15985/wsman" || r.Command != "--context untouched" {
				t.Errorf("unexpected request (credentials omitted)")
			}
			return 37, nil
		}})
		if rc != 37 || !called {
			t.Fatalf("rc=%d: %s", rc, &stderr)
		}
	}
	var output strings.Builder
	rc := Run(t.Context(), []string{"--config", path, "config", "view"}, Deps{Stdout: &output, Stderr: &output, Getenv: func(string) string { return "" }})
	if rc != 0 || strings.Contains(output.String(), "plain-test-secret") || !strings.Contains(output.String(), "REDACTED") {
		t.Fatalf("view failed or leaked password")
	}
}

func TestConfigOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `current_context: test
hosts:
  windows: {endpoint: 'http://localhost:15985/wsman'}
  other: {endpoint: 'http://localhost:25985/wsman'}
credentials:
  account: {user: 'env:MISSING', password: 'env:MISSING', env_file: missing.env, domain: EXAMPLE}
contexts:
  test: {host: windows, credentials: account}
  stage: {host: other, credentials: account}
defaults: {timeout: invalid, auth: invalid}
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name               string
		args               []string
		endpoint, password string
	}{
		{"stdin", []string{"--password-stdin"}, "http://localhost:15985/wsman", "stdin-secret"},
		{"env", []string{"--password-env", "OTHER_PASSWORD"}, "http://localhost:15985/wsman", "env-secret"},
		{"context", []string{"--context", "stage", "--password-stdin"}, "http://localhost:25985/wsman", "stdin-secret"},
		{"alias", []string{"other", "--password-stdin"}, "http://localhost:25985/wsman", "stdin-secret"},
		{"endpoint", []string{"--endpoint", "http://localhost:35985/wsman", "--password-stdin"}, "http://localhost:35985/wsman", "stdin-secret"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"ps", "--user", `OTHER\bob`, "--timeout", "1s", "--auth", "ntlm"}
			args = append(args, tt.args...)
			args = append(args, "--", "hostname")
			var output strings.Builder
			rc := Run(t.Context(), args, Deps{Stdout: io.Discard, Stderr: &output, Stdin: strings.NewReader("stdin-secret\n"), Getenv: func(name string) string {
				switch name {
				case "WINSH_CONFIG":
					return path
				case "OTHER_PASSWORD":
					return "env-secret"
				}
				return ""
			}, Execute: func(ctx context.Context, r remote.Request, _, _ io.Writer) (int, error) {
				if r.User != `OTHER\bob` || r.Password != tt.password || r.Endpoint != tt.endpoint {
					t.Error("flag override failed")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("missing deadline")
				}
				return 37, nil
			}})
			if rc != 37 {
				t.Fatalf("rc=%d: %s", rc, &output)
			}
		})
	}
}
