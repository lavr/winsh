//go:build linux || darwin

package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func shortControlDir(t *testing.T) string {
	t.Helper()
	root := "/tmp"
	if runtime.GOOS == "darwin" {
		root = "/private/tmp"
	}
	dir, err := os.MkdirTemp(root, "wsh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestSocketRejectsUnsafeDirectoryAndSocket(t *testing.T) {
	dir := shortControlDir(t)
	path := filepath.Join(dir, "c.sock")
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(path); err == nil {
		t.Fatal("accepted world-readable runtime directory")
	}
	if _, err := Check(t.Context(), path, testIdentity(), time.Second); err == nil {
		t.Fatal("status check accepted world-readable runtime directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := socketState(path); err == nil {
		t.Fatal("accepted symlink control socket")
	}
}

func TestBootstrapEnvironmentKeepsTrustWithoutPassword(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "synthetic-password")
	t.Setenv("SSL_CERT_FILE", "/tmp/example-ca.pem")
	t.Setenv("GODEBUG", "x509sha1=1")
	env := strings.Join(minimalChildEnv(), "\n")
	if !strings.Contains(env, "SSL_CERT_FILE=/tmp/example-ca.pem") || !strings.Contains(env, "GODEBUG=x509sha1=1") || strings.Contains(env, "synthetic-password") || strings.Contains(env, "WINRM_PASSWORD") {
		t.Fatalf("child environment did not preserve only trust settings: %q", env)
	}
}

func TestBootstrapEnvironmentResolvesRelativeCAPaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("SSL_CERT_FILE", "ca.pem")
	t.Setenv("SSL_CERT_DIR", "roots:more-roots")
	env := strings.Join(minimalChildEnv(), "\n")
	if !strings.Contains(env, "SSL_CERT_FILE="+filepath.Join(dir, "ca.pem")) || !strings.Contains(env, "SSL_CERT_DIR="+filepath.Join(dir, "roots")+":"+filepath.Join(dir, "more-roots")) {
		t.Fatalf("child inherited CA paths relative to a different cwd: %q", env)
	}
}

func TestSocketStaleOwnedRecovery(t *testing.T) {
	configureTestChild(t, 0)
	dir := shortControlDir(t)
	path := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	settings := Settings{Mode: "auto", Path: path, Persist: time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := StartOrConnect(ctx, identity, settings, testBootstrap(identity))
	if err != nil || got != path {
		t.Fatalf("stale recovery = %q, %v", got, err)
	}
	if live, _, err := probeMaster(ctx, path, controlTarget{Identity: identity, Persist: settings.Persist}); !live || err != nil {
		t.Fatalf("new master not ready: %v", err)
	}
}

func TestSocketBusyLockNeverUnlinksConnectedSocket(t *testing.T) {
	dir := shortControlDir(t)
	path := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := openLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if acquired, err := tryLock(lock); !acquired || err != nil {
		t.Fatalf("lock: %v", err)
	}
	// This listener accepts connections but does not answer checks, as can
	// happen while another starter is still bringing up its child.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); <-time.After(time.Second) }()
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	_, err = StartOrConnect(ctx, testIdentity(), Settings{Mode: "auto", Path: path, Persist: time.Second}, func() (Bootstrap, error) {
		t.Error("resolver called while another starter owns lock")
		return Bootstrap{}, errors.New("unexpected")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy lock = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("live socket was unlinked: %v", err)
	}
}
