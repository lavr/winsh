//go:build linux || darwin

package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lavr/winsh/internal/remote"
	"golang.org/x/sys/unix"
)

type testPoster struct{}

func (testPoster) Post(context.Context, string) (string, error) { return "", ErrProtocol }

func TestMasterHelper(t *testing.T) {
	if os.Getenv("WINSH_TEST_CONTROL_CHILD") != "1" {
		return
	}
	delay, _ := time.ParseDuration(os.Getenv("WINSH_TEST_CONTROL_AUTH_DELAY"))
	err := serveWithAuth(context.Background(), 3, func(ctx context.Context, r remote.Request) (remote.Poster, remote.Poster, func(), error) {
		if os.Getenv("WINSH_TEST_CONTROL_TLS") == "1" {
			_, _, closeBoth, err := remote.NewPersistentPosters(ctx, r)
			if err == nil {
				closeBoth()
				return nil, nil, nil, errors.New("synthetic TLS fixture unexpectedly authenticated")
			}
			if !strings.Contains(err.Error(), "expected NTLM authentication challenge") {
				return nil, nil, nil, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-time.After(delay):
		}
		return testPoster{}, testPoster{}, func() {}, nil
	})
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestBootstrapPreservesTLSRootsAndRejectsWrongCA(t *testing.T) {
	t.Setenv("SSL_CERT_DIR", "")
	configureTestChild(t, 0)
	baseEnvironment := childEnvironment
	childEnvironment = func() []string { return append(baseEnvironment(), "WINSH_TEST_CONTROL_TLS=1") }
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	writeCA := func(name string, cert []byte) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	goodCA := writeCA("good.pem", server.TLS.Certificates[0].Certificate[0])
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "unrelated.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	wrongCert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wrongCA := writeCA("wrong.pem", wrongCert)
	identity := Identity{Endpoint: server.URL + "/wsman", User: `EXAMPLE\alice`}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	t.Setenv("SSL_CERT_FILE", goodCA)
	identity.TrustKey = TrustKey(os.Getenv)
	path := filepath.Join(shortControlDir(t), "c.sock")
	if _, err := StartOrConnect(ctx, identity, Settings{Mode: "auto", Path: path, Persist: time.Second}, testBootstrap(identity)); err != nil {
		t.Fatalf("child did not inherit configured CA: %v", err)
	}
	if err := Exit(ctx, path, identity, time.Second); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", wrongCA)
	identity.TrustKey = TrustKey(os.Getenv)
	wrongPath := filepath.Join(shortControlDir(t), "c.sock")
	if _, err := StartOrConnect(ctx, identity, Settings{Mode: "auto", Path: wrongPath, Persist: time.Second}, testBootstrap(identity)); err == nil {
		t.Fatal("wrong CA was accepted by child")
	}
	if _, err := os.Lstat(wrongPath); err == nil {
		t.Fatal("failed TLS authentication left a ready socket")
	}
}

func configureTestChild(t *testing.T, delay time.Duration) {
	t.Helper()
	oldCommand, oldEnvironment := childCommand, childEnvironment
	childCommand = func() (*exec.Cmd, error) {
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return exec.Command(executable, "-test.run=^TestMasterHelper$"), nil
	}
	childEnvironment = func() []string {
		return append(minimalChildEnv(), "WINSH_TEST_CONTROL_CHILD=1", "WINSH_TEST_CONTROL_AUTH_DELAY="+delay.String())
	}
	t.Cleanup(func() { childCommand, childEnvironment = oldCommand, oldEnvironment })
}

func testIdentity() Identity {
	return Identity{Endpoint: "http://server.example.com:5985/wsman", User: `EXAMPLE\alice`, TrustKey: "synthetic-trust"}
}

func testBootstrap(identity Identity) func() (Bootstrap, error) {
	return func() (Bootstrap, error) {
		return Bootstrap{Endpoint: identity.Endpoint, User: identity.User, TargetHost: identity.TargetHost, Password: "synthetic-password", Timeout: time.Second}, nil
	}
}

func TestMasterStartsReusesAndIdles(t *testing.T) {
	configureTestChild(t, 0)
	path := filepath.Join(shortControlDir(t), "c.sock")
	identity := testIdentity()
	settings := Settings{Mode: "auto", Path: path, Persist: 350 * time.Millisecond}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := StartOrConnect(ctx, identity, settings, testBootstrap(identity))
	if err != nil || got != path {
		t.Fatalf("start = %q, %v", got, err)
	}
	got, err = StartOrConnect(ctx, identity, settings, func() (Bootstrap, error) {
		t.Error("resolved password despite ready master")
		return Bootstrap{}, ErrProtocol
	})
	if err != nil || got != path {
		t.Fatalf("reuse = %q, %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %v, %v", info, err)
	}
	if _, err := StartOrConnect(ctx, identity, Settings{Mode: "auto", Path: path, Persist: time.Second}, func() (Bootstrap, error) {
		t.Error("resolved password despite persist mismatch")
		return Bootstrap{}, ErrProtocol
	}); err == nil {
		t.Fatal("accepted different idle persistence")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle master left socket behind")
}

func TestMasterConcurrentStartersShareOneChild(t *testing.T) {
	configureTestChild(t, 250*time.Millisecond)
	identity := testIdentity()
	settings := Settings{Mode: "auto", Path: filepath.Join(shortControlDir(t), "c.sock"), Persist: time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var resolved atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := StartOrConnect(ctx, identity, settings, func() (Bootstrap, error) {
				resolved.Add(1)
				return testBootstrap(identity)()
			})
			if err != nil {
				t.Errorf("starter: %v", err)
			}
		}()
	}
	wg.Wait()
	if resolved.Load() != 1 {
		t.Fatalf("resolved credentials %d times", resolved.Load())
	}
}

func TestBootstrapCancellationBeforeReadiness(t *testing.T) {
	configureTestChild(t, time.Second)
	identity := testIdentity()
	path := filepath.Join(shortControlDir(t), "c.sock")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := StartOrConnect(ctx, identity, Settings{Mode: "auto", Path: path, Persist: time.Second}, testBootstrap(identity))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap timeout = %v", err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("canceled bootstrap left a socket")
	}
}

func TestMasterRejectsOtherIdentity(t *testing.T) {
	configureTestChild(t, 0)
	identity := testIdentity()
	path := filepath.Join(shortControlDir(t), "c.sock")
	settings := Settings{Mode: "auto", Path: path, Persist: time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := StartOrConnect(ctx, identity, settings, testBootstrap(identity)); err != nil {
		t.Fatal(err)
	}
	other := identity
	other.User = `EXAMPLE\bob`
	_, err := StartOrConnect(ctx, other, settings, func() (Bootstrap, error) {
		t.Error("resolved password for mismatched socket")
		return Bootstrap{}, ErrProtocol
	})
	var category CategoryError
	if !errors.As(err, &category) || category.Category != CategoryIdentityMismatch {
		t.Fatalf("identity mismatch = %v", err)
	}
}

func TestBootstrapParentDisconnect(t *testing.T) {
	configureTestChild(t, time.Second)
	identity := testIdentity()
	path := filepath.Join(shortControlDir(t), "c.sock")
	lock, err := openLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if acquired, err := tryLock(lock); !acquired || err != nil {
		t.Fatalf("lock: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parent, child := os.NewFile(uintptr(fds[0]), "parent"), os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	defer child.Close()
	command, err := childCommand()
	if err != nil {
		t.Fatal(err)
	}
	command.ExtraFiles = []*os.File{child, lock}
	command.Env = childEnvironment()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	boot, _ := testBootstrap(identity)()
	boot.Identity, boot.Socket, boot.Persist = identity, path, time.Second
	if err := json.NewEncoder(parent).Encode(boot); err != nil {
		t.Fatal(err)
	}
	// The parent vanishes after sending credentials but before readiness.
	parent.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("child accepted lost parent")
		}
	case <-time.After(700 * time.Millisecond):
		_ = command.Process.Kill()
		<-done
		t.Fatal("child ignored bootstrap pipe EOF")
	}
	if _, err := net.DialTimeout("unix", path, 20*time.Millisecond); err == nil {
		t.Fatal("orphan master became ready")
	}
}
