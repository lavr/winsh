package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

type poster interface {
	post(context.Context, string) (string, error)
}

// Run executes one command over two persistent NTLM connections: the command
// connection carries Create, Command, Send and Receive, and a pre-authenticated
// cleanup connection, kept open by heartbeats, carries Signal and Delete when
// the command connection is interrupted. Cleanup then costs two SOAP exchanges
// instead of a new NTLM handshake per request, so it fits its five-second
// budget on slow links.
func Run(ctx context.Context, r Request, stdout, stderr io.Writer) (int, error) {
	command, cleanup, closeBoth, err := NewPersistentPosters(ctx, r)
	if err != nil {
		return 0, err
	}
	defer closeBoth()
	stop := keepLanesAlive(ctx, HeartbeatInterval, command, cleanup)
	defer stop()
	// A Delete the lanes could not send, for example after a failed
	// heartbeat, falls back to a freshly authenticated connection.
	rc, runErr, cleanupErr := runWithPosters(ctx, r, stdout, stderr, command, cleanup, newTransport(r))
	if runErr == nil && cleanupErr != nil {
		return rc, completedCleanupError(cleanupErr)
	}
	return rc, errors.Join(runErr, cleanupErr)
}

// completedCleanupError reports a cleanup failure after the command finished.
// It keeps whether Shell deletion is uncertain but drops the cleanup budget's
// own deadline, which is not the command's timeout.
func completedCleanupError(err error) error {
	outcome := ErrCleanupFailed
	if errors.Is(err, ErrRemoteStateUnknown) {
		outcome = ErrRemoteStateUnknown
	}
	return fmt.Errorf("remote command completed but shell cleanup failed: %w", outcome)
}

// run executes r.Command against a WinRM endpoint and drains the command's
// stdout/stderr into the supplied writers. It opens a shell, starts the
// command, closes stdin, then loops WSMan Receive until the command
// exits. The session helper owns shell lifecycle and receive polling;
// run() only handles transfer-level concerns: the codepage transform for
// non-UTF8 cmd output and the fixed five-second cleanup budget. The
// cleanup budget starts only when we are about to close the shell; a
// long-running command must not eat into the cleanup window.
func run(ctx context.Context, r Request, stdout, stderr io.Writer, p poster) (int, error) {
	return runWithCleanup(ctx, r, stdout, stderr, p, p, nil)
}

// runWithCleanup is run with Delete sent through cleanup, or through
// fallback when cleanup could not send it.
func runWithCleanup(ctx context.Context, r Request, stdout, stderr io.Writer, p, cleanup, fallback poster) (code int, runErr error) {
	s, err := startSessionLanes(ctx, r, p, cleanup, p, p, fallback)
	if err != nil {
		return 0, err
	}

	defer func() {
		// Detach from the caller's ctx so a cancellation does not abort
		// the delete; start the timer here so a 30-second command does
		// not consume the cleanup budget.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.close(cleanup); err != nil && runErr == nil {
			runErr = errors.New("remote command completed but shell cleanup failed")
		}
	}()

	// Non-interactive commands see EOF instead of waiting on an unconnected
	// stdin. send is synchronous: the EOF is fully delivered before run()
	// returns to the receive loop.
	if err := s.send(ctx, nil, true); err != nil {
		return 0, err
	}

	stdout, stderr = decodeWriters(r, stdout, stderr)
	rc, err := s.receive(ctx, stdout, stderr)
	if err != nil {
		return 0, err
	}
	return rc, nil
}

func decodeWriters(r Request, stdout, stderr io.Writer) (io.Writer, io.Writer) {
	if !r.PowerShell {
		switch r.Codepage {
		case "866":
			dec := charmap.CodePage866.NewDecoder()
			stdout = transform.NewWriter(stdout, dec)
			stderr = transform.NewWriter(stderr, dec)
		case "1251":
			dec := charmap.Windows1251.NewDecoder()
			stdout = transform.NewWriter(stdout, dec)
			stderr = transform.NewWriter(stderr, dec)
		}
	}
	return stdout, stderr
}
