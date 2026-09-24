//go:build linux || darwin

package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errMasterUnresponsive = errors.New("local control master is unresponsive")

type controlTarget struct {
	Identity Identity
	Persist  time.Duration
}

func socketPath(identity Identity, settings Settings) (string, error) {
	if settings.Path != "" {
		if !filepath.IsAbs(settings.Path) || filepath.Clean(settings.Path) != settings.Path {
			return "", errors.New("control path must be absolute and clean")
		}
		return settings.Path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot locate control runtime directory")
	}
	return filepath.Join(home, ".winsh", identity.Key()+".sock"), nil
}

// SocketPath derives a private socket pathname without resolving credentials.
func SocketPath(identity Identity, settings Settings) (string, error) {
	return socketPath(identity, settings)
}

// Check probes an existing master without creating one or reading a password.
func Check(ctx context.Context, socket string, identity Identity, persist time.Duration) (bool, error) {
	dirExists, err := checkSocketDirectory(socket)
	if err != nil || !dirExists {
		return false, err
	}
	exists, _, err := socketState(socket)
	if err != nil || !exists {
		return false, err
	}
	live, _, err := probeMaster(ctx, socket, controlTarget{Identity: identity, Persist: persist})
	return live, err
}

// Exit asks a matching master to stop admission and wait for active work.
func Exit(ctx context.Context, socket string, identity Identity, persist time.Duration) error {
	dirExists, err := checkSocketDirectory(socket)
	if err != nil {
		return err
	}
	if !dirExists {
		return CategoryError{Category: CategoryUnavailable}
	}
	exists, _, err := socketState(socket)
	if err != nil {
		return err
	}
	if !exists {
		return CategoryError{Category: CategoryUnavailable}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := writeJSONFrame(conn, frameExit, controlTarget{Identity: identity, Persist: persist}); err != nil {
		return transportError(ctx, err)
	}
	kind, payload, err := readFrame(conn)
	if err != nil {
		return transportError(ctx, err)
	}
	if kind != frameResult {
		return ErrProtocol
	}
	var result Result
	if decodeStrictJSON(payload, &result) != nil || result.Category != "" && !validCategory(result.Category) {
		return ErrProtocol
	}
	if result.Category != "" {
		return CategoryError{Category: result.Category}
	}
	return nil
}

func checkSocketDirectory(path string) (bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) >= 104 {
		return false, errors.New("invalid control socket path")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
		return false, errors.New("control runtime directory must be user-owned mode 0700")
	}
	return true, nil
}

func prepareSocketPath(path string) error {
	if len(path) >= 104 {
		return errors.New("control socket path is too long")
	}
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("cannot create control runtime directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
		return errors.New("control runtime directory must be user-owned mode 0700")
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func socketState(path string) (exists, stale bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, errors.New("cannot inspect control socket")
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
		return true, false, errors.New("control socket has unsafe owner, type or permissions")
	}
	return true, true, nil
}

func openLock(path string) (*os.File, error) {
	lockPath := path + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open control lock")
	}
	file := os.NewFile(uintptr(fd), lockPath)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
		file.Close()
		return nil, errors.New("control lock has unsafe owner, type or permissions")
	}
	return file, nil
}

func tryLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return false, errors.New("cannot lock control socket")
}

func probeMaster(ctx context.Context, path string, target controlTarget) (bool, bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "unix", path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return false, false, nil
		}
		return false, false, err
	}
	defer conn.Close()
	deadline, _ := probeCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	if err := writeJSONFrame(conn, frameCheck, target); err != nil {
		return false, true, errMasterUnresponsive
	}
	kind, payload, err := readFrame(conn)
	if err != nil || kind != frameResult {
		return false, true, errMasterUnresponsive
	}
	var result Result
	if decodeStrictJSON(payload, &result) != nil {
		return false, true, errMasterUnresponsive
	}
	if result.Category != "" {
		if !validCategory(result.Category) {
			return false, true, errMasterUnresponsive
		}
		return false, true, CategoryError{Category: result.Category}
	}
	return true, true, nil
}

func minimalChildEnv() []string {
	var env []string
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG"} {
		if value, ok := os.LookupEnv(name); ok && !strings.ContainsRune(value, 0) {
			switch name {
			case "SSL_CERT_FILE":
				value = effectiveCAFile(value)
			case "SSL_CERT_DIR":
				value = effectiveCADirs(value)
			}
			env = append(env, name+"="+value)
		}
	}
	return env
}
