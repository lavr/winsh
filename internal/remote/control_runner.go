package remote

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrRemoteStateUnknown means the outcome of a dispatched request is uncertain:
// a Shell may exist that cleanup could not confirm deleted. It contains no
// server-supplied text.
var ErrRemoteStateUnknown = errors.New("remote state unknown")

// ErrNotStarted means the Shell Create request was never sent, so no remote
// Shell or command exists. It is matched with errors.Is and never changes the
// wrapped error's text.
var ErrNotStarted = errors.New("remote command was not started")

// errUnsent marks a failure proven to precede sending one SOAP request. Only
// an unsent Shell Create means the command did not start; an unsent Send or
// Receive belongs to a command that is already running.
var errUnsent = errors.New("SOAP request was not sent")

type markedError struct {
	error
	mark error
}

func (e markedError) Unwrap() error        { return e.error }
func (e markedError) Is(target error) bool { return target == e.mark }

func unsent(err error) error     { return markedError{err, errUnsent} }
func notStarted(err error) error { return markedError{err, ErrNotStarted} }

// ErrCleanupFailed means Shell deletion was confirmed, but another required
// cleanup step failed.
var ErrCleanupFailed = errors.New("remote command cleanup failed")

type posterAdapter struct{ Poster }

func (p posterAdapter) post(ctx context.Context, body string) (string, error) {
	return p.Poster.Post(ctx, body)
}

// RunWithPosters executes an independent WinRS command using a preauthenticated
// command connection. A separate connection remains available for cleanup if
// the command lane becomes unusable or the caller cancels.
func RunWithPosters(ctx context.Context, r Request, stdout, stderr io.Writer, command, cleanup Poster) (int, error) {
	code, runErr, cleanupErr := runWithPosters(ctx, r, stdout, stderr, command, cleanup, nil)
	return code, errors.Join(runErr, cleanupErr)
}

// runWithPosters reports the command's own error and the cleanup error
// separately. A completed command's Shell is deleted on the command lane; an
// interrupted one is signaled and deleted on the cleanup lane. fallback, when
// set, retries a Delete that the lanes could not send.
func runWithPosters(ctx context.Context, r Request, stdout, stderr io.Writer, command, cleanup Poster, fallback poster) (code int, runErr, cleanupErr error) {
	if command == nil || cleanup == nil {
		return 0, errors.New("missing authenticated connection"), nil
	}
	commandPost, cleanupPost := posterAdapter{command}, posterAdapter{cleanup}
	s, err := startSessionLanes(ctx, r, commandPost, cleanupPost, commandPost, commandPost, fallback)
	if err != nil {
		return 0, err, nil
	}
	defer func() {
		budget, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		// A finished command needs only Delete. Signal stops an
		// interrupted one, on the lane that no exchange left broken.
		if runErr != nil || ctx.Err() != nil {
			cleanupErr = s.closeWith(budget, cleanupPost, cleanupPost, true)
		} else {
			cleanupErr = s.closeWith(budget, commandPost, cleanupPost, false)
		}
	}()
	if err := s.send(ctx, nil, true); err != nil {
		return 0, err, nil
	}
	stdout, stderr = decodeWriters(r, stdout, stderr)
	code, runErr = s.receive(ctx, stdout, stderr)
	return code, runErr, nil
}
