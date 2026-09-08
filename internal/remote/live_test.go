//go:build integration

package remote

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveWindows executes only harmless commands. No workstation credentials
// are inferred: the caller must explicitly configure all three variables.
func TestLiveWindows(t *testing.T) {
	endpoint, user, password := os.Getenv("WINSH_TEST_ENDPOINT"), os.Getenv("WINSH_TEST_USER"), os.Getenv("WINSH_TEST_PASSWORD")
	if endpoint == "" {
		t.Skip("set WINSH_TEST_ENDPOINT, WINSH_TEST_USER and WINSH_TEST_PASSWORD for live Windows validation")
	}
	if user == "" || password == "" {
		t.Fatal("live test credentials are incomplete")
	}
	endpoint, err := Endpoint("", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, command, want string
		ps                  bool
		rc                  int
	}{
		{"cmd", "echo winsh-smoke & exit /b 37", "winsh-smoke", false, 37},
		{"powershell", "Write-Output 'Привет 😀'; exit 17", "Привет 😀", true, 17},
		{"stderr", "[Console]::Error.WriteLine('winsh-stderr'); exit 19", "", true, 19},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var out, stderr bytes.Buffer
			rc, err := Run(ctx, Request{Endpoint: endpoint, TargetHost: os.Getenv("WINSH_TEST_TARGET_HOST"), User: user, Password: password, Command: tt.command, PowerShell: tt.ps}, &out, &stderr)
			if err != nil {
				t.Fatal(strings.ReplaceAll(err.Error(), password, "[REDACTED]"))
			}
			if rc != tt.rc || !strings.Contains(out.String(), tt.want) {
				t.Errorf("unexpected output or exit code (rc=%d)", rc)
			}
			if tt.name == "stderr" && !strings.Contains(stderr.String(), "winsh-stderr") {
				t.Error("stderr missing")
			}
		})
	}
}
