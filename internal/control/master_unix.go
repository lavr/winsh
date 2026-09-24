//go:build linux || darwin

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/lavr/winsh/internal/remote"
	"golang.org/x/sys/unix"
)

const bootstrapLimit = 64 * 1024
const bootstrapTimeout = 30 * time.Second

type Bootstrap struct {
	Endpoint, User, Password, TargetHost string
	Timeout                              time.Duration
	Identity                             Identity
	Socket                               string
	Persist                              time.Duration
}

var childCommand = func() (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.Command(executable, "__control-master"), nil
}

var childEnvironment = minimalChildEnv

var authenticateMaster = func(ctx context.Context, r remote.Request) (remote.Poster, remote.Poster, func(), error) {
	return remote.NewPersistentPosters(ctx, r)
}

// StartOrConnect returns a matching master socket. The resolver is called only
// after a verified lookup, under the per-path lock, finds no usable master.
func StartOrConnect(ctx context.Context, identity Identity, settings Settings, resolve func() (Bootstrap, error)) (string, error) {
	if settings.Mode != "auto" || settings.Persist <= 0 || settings.Persist > time.Hour {
		return "", errors.New("invalid control settings")
	}
	path, err := socketPath(identity, settings)
	if err != nil {
		return "", err
	}
	if err := prepareSocketPath(path); err != nil {
		return "", err
	}
	startupCtx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()
	target := controlTarget{Identity: identity, Persist: settings.Persist}
	for {
		exists, _, err := socketState(path)
		if err != nil {
			return "", err
		}
		if exists {
			live, connected, probeErr := probeMaster(startupCtx, path, target)
			if live {
				return path, nil
			}
			if probeErr != nil && (!errors.Is(probeErr, errMasterUnresponsive) || !connected) {
				return "", probeErr
			}
		}
		lock, err := openLock(path)
		if err != nil {
			return "", err
		}
		acquired, err := tryLock(lock)
		if err != nil {
			lock.Close()
			return "", err
		}
		if !acquired {
			lock.Close()
			select {
			case <-startupCtx.Done():
				return "", startupCtx.Err()
			case <-time.After(25 * time.Millisecond):
				continue
			}
		}
		// The lock is held here. A socket that still accepts connections
		// but misses a short probe may be a slow master; never unlink it.
		exists, _, err = socketState(path)
		if err != nil {
			lock.Close()
			return "", err
		}
		if exists {
			live, connected, probeErr := probeMaster(startupCtx, path, target)
			if live {
				lock.Close()
				return path, nil
			}
			if connected {
				lock.Close()
				if probeErr != nil {
					return "", probeErr
				}
				return "", errMasterUnresponsive
			}
			// A refused socket, with the lock held and owner/type/mode
			// verified, is stale. No command can be active there.
			if err := os.Remove(path); err != nil {
				lock.Close()
				return "", errors.New("cannot remove stale control socket")
			}
		}
		if startupCtx.Err() != nil {
			lock.Close()
			return "", startupCtx.Err()
		}
		boot, err := resolve()
		if err != nil {
			lock.Close()
			return "", err
		}
		boot.Identity, boot.Socket, boot.Persist = identity, path, settings.Persist
		if boot.Endpoint != identity.Endpoint || boot.User != identity.User || boot.TargetHost != identity.TargetHost {
			lock.Close()
			return "", errors.New("control bootstrap target mismatch")
		}
		if err := startupCtx.Err(); err != nil {
			boot.Password = ""
			lock.Close()
			return "", err
		}
		err = launchMaster(startupCtx, lock, boot)
		boot.Password = ""
		if err != nil {
			return "", err
		}
		return path, nil
	}
}

func launchMaster(ctx context.Context, lock *os.File, boot Bootstrap) error {
	defer lock.Close()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return errors.New("cannot create private control bootstrap")
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parent := os.NewFile(uintptr(fds[0]), "control-parent")
	child := os.NewFile(uintptr(fds[1]), "control-child")
	defer parent.Close()
	defer child.Close()
	cmd, err := childCommand()
	if err != nil {
		return errors.New("cannot locate control master executable")
	}
	cmd.ExtraFiles = []*os.File{child, lock}
	cmd.Env = childEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start control master")
	}
	child.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("cannot open private control bootstrap")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(boot); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("cannot send control bootstrap")
	}
	boot.Password = ""
	kind, payload, err := readFrame(conn)
	if err != nil || kind != frameResult {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("control master did not become ready")
	}
	var result Result
	if json.Unmarshal(payload, &result) != nil || result.Category != "" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("control master authentication failed")
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Serve enters the hidden child mode using an inherited private socket at fd
// 3 and the held per-path lock at fd 4. Neither descriptor is a public IPC
// channel and the bootstrap password is never carried in argv or environment.
func Serve(ctx context.Context, bootstrapFD uintptr) error {
	return serveWithAuth(ctx, bootstrapFD, authenticateMaster)
}

func serveWithAuth(ctx context.Context, bootstrapFD uintptr, auth func(context.Context, remote.Request) (remote.Poster, remote.Poster, func(), error)) error {
	lock := os.NewFile(bootstrapFD+1, "control-lock")
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() || !ownedByCurrentUser(info) {
		return errors.New("invalid inherited control lock")
	}
	pipe := os.NewFile(bootstrapFD, "control-bootstrap")
	defer pipe.Close()
	conn, err := net.FileConn(pipe)
	if err != nil {
		return errors.New("invalid inherited control bootstrap")
	}
	defer conn.Close()
	deadline := time.Now().Add(bootstrapTimeout)
	_ = conn.SetDeadline(deadline)
	bootstrapCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(bootstrapCtx, func() { _ = conn.Close() })
	defer stop()
	var boot Bootstrap
	if json.NewDecoder(io.LimitReader(conn, bootstrapLimit)).Decode(&boot) != nil {
		return errors.New("cannot read control bootstrap")
	}
	if boot.Socket == "" || boot.Persist < MinPersist || boot.Persist > time.Hour || boot.Endpoint != boot.Identity.Endpoint || boot.User != boot.Identity.User || boot.TargetHost != boot.Identity.TargetHost {
		return errors.New("invalid control bootstrap target")
	}
	// Parent disappearance before readiness cancels authentication. The
	// bootstrap pipe is private and has no further application messages.
	go func() { _, _ = io.Copy(io.Discard, conn); cancel() }()
	request := remote.Request{Endpoint: boot.Endpoint, User: boot.User, Password: boot.Password, TargetHost: boot.TargetHost}
	command, cleanup, closeBoth, err := auth(bootstrapCtx, request)
	request.Password, boot.Password = "", ""
	if err != nil {
		_ = writeJSONFrame(conn, frameResult, Result{Category: CategoryUnavailable})
		return errors.New("control authentication failed")
	}
	defer closeBoth()
	if err := prepareSocketPath(boot.Socket); err != nil {
		return err
	}
	// The child owns its process umask. Bind the socket with mode 0600 from
	// the first instant it exists, before concurrent starters can inspect it.
	unix.Umask(0177)
	listener, err := net.Listen("unix", boot.Socket)
	if err != nil {
		return errors.New("cannot bind control socket")
	}
	defer listener.Close()
	if err := os.Chmod(boot.Socket, 0600); err != nil {
		return errors.New("cannot secure control socket")
	}
	if err := writeJSONFrame(conn, frameResult, Result{}); err != nil {
		return errors.New("cannot signal control readiness")
	}
	_ = conn.Close()
	_ = pipe.Close()
	return serveReady(ctx, listener, boot.Identity, boot.Persist, command, cleanup)
}

func serveReady(ctx context.Context, listener net.Listener, identity Identity, persist time.Duration, command, cleanup remote.Poster) error {
	execute := func(ctx context.Context, call Call, stdout, stderr io.Writer) (int, error) {
		request := remote.Request{Endpoint: identity.Endpoint, TargetHost: identity.TargetHost, User: identity.User, Command: call.Command, PowerShell: call.PowerShell, Codepage: call.Codepage}
		return remote.RunWithPosters(ctx, request, stdout, stderr, command, cleanup)
	}
	server := newMasterServer(ctx, listener, identity, persist, execute)
	server.heartbeat = func(ctx context.Context) error {
		for _, lane := range []remote.Poster{command, cleanup} {
			if err := keepAliveLane(ctx, lane); err != nil {
				return err
			}
		}
		return nil
	}
	server.heartbeatEvery = heartbeatInterval
	return server.serve()
}

// Windows HTTP.sys closes idle connections after 120 seconds by default, and
// an administrator may lower that. A lane idle for heartbeatInterval gets an
// Identify at the next tick, so it is never idle much beyond twice that.
// heartbeatTimeout bounds how long a cleanup waits behind a heartbeat on its
// lane, within the five-second cleanup budget.
const (
	heartbeatInterval = 30 * time.Second
	heartbeatTimeout  = 2 * time.Second
)

type keepAliver interface {
	KeepAlive(context.Context, time.Duration) error
}

func keepAliveLane(ctx context.Context, lane remote.Poster) error {
	k, ok := lane.(keepAliver)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
	defer cancel()
	return k.KeepAlive(ctx, heartbeatInterval)
}
