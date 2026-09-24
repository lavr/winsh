package remote

import (
	"context"
	"errors"
	"io"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

type poster interface {
	post(context.Context, string) (string, error)
}

func Run(ctx context.Context, r Request, stdout, stderr io.Writer) (int, error) {
	return run(ctx, r, stdout, stderr, newTransport(r))
}

// run executes r.Command against a WinRM endpoint and drains the command's
// stdout/stderr into the supplied writers. It opens a shell, starts the
// command, closes stdin, then loops WSMan Receive until the command
// exits. The session helper owns shell lifecycle and receive polling;
// run() only handles transfer-level concerns: the codepage transform for
// non-UTF8 cmd output and the fixed five-second cleanup budget. The
// cleanup budget starts only when we are about to close the shell; a
// long-running command must not eat into the cleanup window.
func run(ctx context.Context, r Request, stdout, stderr io.Writer, p poster) (code int, runErr error) {
	s, err := startSession(ctx, r, p)
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
