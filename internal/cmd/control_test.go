package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lavr/winsh/internal/control"
	"github.com/lavr/winsh/internal/remote"
)

type mustNotRead struct{ t *testing.T }

func (m mustNotRead) Read([]byte) (int, error) {
	m.t.Error("password stdin was read while reusing a master")
	return 0, io.EOF
}

func TestControlAutoReusesWithoutPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run(t.Context(), []string{"run", "server.example.com", "--user", "alice", "--control=auto", "--password-stdin", "--", "hostname"}, Deps{
		Stdin: mustNotRead{t}, Stdout: &stdout, Stderr: &stderr,
		Getenv: func(name string) string {
			if name == "WINRM_PASSWORD" {
				t.Error("password environment was read")
			}
			return ""
		},
		Execute: func(context.Context, remote.Request, io.Writer, io.Writer) (int, error) {
			t.Error("standalone path used")
			return 0, nil
		},
		ControlStart: func(_ context.Context, _ control.Identity, _ control.Settings, _ func() (control.Bootstrap, error)) (string, error) {
			return "/private/tmp/synthetic.sock", nil
		},
		ControlInvoke: func(ctx context.Context, socket string, call control.Call, out, errout io.Writer) (control.Result, error) {
			if socket != "/private/tmp/synthetic.sock" || call.Command != "hostname" || call.Identity.User != "alice" || call.Persist != 5*time.Minute || call.Deadline.IsZero() {
				t.Error("wrong control call")
			}
			_, _ = io.WriteString(out, "ok\n")
			_, _ = io.WriteString(errout, "err\n")
			return control.Result{ExitCode: 37}, nil
		},
	})
	if rc != 37 || stdout.String() != "ok\n" || stderr.String() != "err\n" {
		t.Fatalf("reuse rc=%d out=%q err=%q", rc, stdout.String(), stderr.String())
	}
}

func TestControlAutoBootstrapReadsPasswordOnce(t *testing.T) {
	reads := 0
	var stderr bytes.Buffer
	rc := Run(t.Context(), []string{"ps", "server.example.com", "--user", "alice", "--control=auto", "--", "Get-Date"}, Deps{
		Stdin: mustNotRead{t}, Stdout: io.Discard, Stderr: &stderr,
		Getenv: func(name string) string {
			if name == "WINRM_PASSWORD" {
				reads++
				return "synthetic-password"
			}
			return ""
		},
		ControlStart: func(_ context.Context, _ control.Identity, _ control.Settings, resolve func() (control.Bootstrap, error)) (string, error) {
			boot, err := resolve()
			if err != nil || boot.Password != "synthetic-password" || boot.Endpoint == "" {
				t.Error("bad bootstrap")
			}
			return "synthetic.sock", nil
		},
		ControlInvoke: func(_ context.Context, _ string, call control.Call, _, _ io.Writer) (control.Result, error) {
			if !call.PowerShell {
				t.Error("ps mode lost")
			}
			return control.Result{}, nil
		},
	})
	if rc != 0 || reads != 1 {
		t.Fatalf("bootstrap rc=%d reads=%d err=%s", rc, reads, &stderr)
	}
}

func TestControlCheckExitSkipPassword(t *testing.T) {
	for _, action := range []string{"check", "exit"} {
		t.Run(action, func(t *testing.T) {
			var output bytes.Buffer
			rc := Run(t.Context(), []string{"control", action, "server.example.com", "--user", "alice", "--password-stdin"}, Deps{
				Stdin: mustNotRead{t}, Stdout: &output, Stderr: &output,
				Getenv: func(name string) string {
					if name == "WINRM_PASSWORD" {
						t.Error("password environment was read")
					}
					return ""
				},
				ControlCheck: func(context.Context, string, control.Identity, time.Duration) (bool, error) { return true, nil },
				ControlExit:  func(context.Context, string, control.Identity, time.Duration) error { return nil },
			})
			if rc != 0 {
				t.Fatalf("control %s rc=%d output=%q", action, rc, output.String())
			}
		})
	}
}

func TestControlFailureCategories(t *testing.T) {
	for _, tt := range []struct {
		category string
		status   int
	}{{control.CategoryTimeout, 203}, {control.CategoryCanceled, 204}, {control.CategoryRemoteStateUnknown, 202}} {
		var stderr bytes.Buffer
		rc := Run(t.Context(), []string{"run", "server.example.com", "--user", "alice", "--control=auto", "--", "hostname"}, Deps{
			Stdout: io.Discard, Stderr: &stderr, Getenv: func(string) string { return "" },
			ControlStart: func(context.Context, control.Identity, control.Settings, func() (control.Bootstrap, error)) (string, error) {
				return "synthetic.sock", nil
			},
			ControlInvoke: func(context.Context, string, control.Call, io.Writer, io.Writer) (control.Result, error) {
				return control.Result{Category: tt.category}, nil
			},
		})
		if rc != tt.status || !bytes.Contains(stderr.Bytes(), []byte(tt.category)) {
			t.Fatalf("category=%q rc=%d stderr=%q", tt.category, rc, stderr.String())
		}
	}
	var stderr bytes.Buffer
	rc := Run(t.Context(), []string{"run", "server.example.com", "--user", "alice", "--control=auto", "--", "hostname"}, Deps{
		Stdout: io.Discard, Stderr: &stderr, Getenv: func(string) string { return "" },
		ControlStart: func(context.Context, control.Identity, control.Settings, func() (control.Bootstrap, error)) (string, error) {
			return "", errors.New("private server details")
		},
	})
	if rc != 202 || bytes.Contains(stderr.Bytes(), []byte("private server details")) {
		t.Fatalf("control error leaked details: rc=%d stderr=%q", rc, stderr.String())
	}
}

func TestControlCanceledCommandReportsUnknownStateWithCancellationStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stderr bytes.Buffer
	rc := controlFailure(ctx, errors.Join(context.Canceled, control.CategoryError{Category: control.CategoryRemoteStateUnknown}), &stderr)
	if rc != 204 || !bytes.Contains(stderr.Bytes(), []byte(control.CategoryRemoteStateUnknown)) {
		t.Fatalf("canceled uncertain command: rc=%d stderr=%q", rc, stderr.String())
	}
}

func TestControlTimeoutReportsUnknownStateOnOneDiagnosticLine(t *testing.T) {
	var stderr bytes.Buffer
	rc := controlFailure(t.Context(), errors.Join(context.DeadlineExceeded, control.CategoryError{Category: control.CategoryRemoteStateUnknown}), &stderr)
	if rc != 203 || bytes.Count(stderr.Bytes(), []byte("\n")) != 1 || !bytes.Contains(stderr.Bytes(), []byte(control.CategoryRemoteStateUnknown)) {
		t.Fatalf("timed out uncertain command: rc=%d stderr=%q", rc, stderr.String())
	}
}

func TestControlHelp(t *testing.T) {
	var output bytes.Buffer
	if rc := Run(t.Context(), []string{"--help"}, Deps{Stdout: &output, Stderr: io.Discard}); rc != 0 {
		t.Fatalf("help status %d", rc)
	}
	for _, fragment := range []string{"--control=auto", "--control-persist", "--control-path", "control check", "control exit"} {
		if !bytes.Contains(output.Bytes(), []byte(fragment)) {
			t.Errorf("help omits %q", fragment)
		}
	}
}
