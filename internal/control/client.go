package control

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"time"
)

// cancelWait bounds how long a canceled or timed-out client waits for the
// master's final result: the master's five-second cleanup budget plus reply
// time.
const cancelWait = 7 * time.Second

type closeWriter interface{ CloseWrite() error }

// Invoke sends one command to a local master and streams output frames to the
// caller's writers. Closing the connection, or only its write side, cancels
// only this command.
func Invoke(ctx context.Context, socket string, call Call, stdout, stderr io.Writer) (Result, error) {
	if err := validateCall(call); err != nil {
		return Result{}, err
	}
	if !call.Deadline.After(time.Now()) {
		return Result{}, context.DeadlineExceeded
	}
	dialCtx, cancel := context.WithDeadline(ctx, call.Deadline)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", socket)
	if err != nil {
		return Result{}, err
	}
	return invokeConn(ctx, conn, call, stdout, stderr)
}

func invokeConn(ctx context.Context, conn net.Conn, call Call, stdout, stderr io.Writer) (Result, error) {
	defer conn.Close()
	if err := validateCall(call); err != nil {
		return Result{}, err
	}
	if stdout == nil || stderr == nil {
		return Result{}, ErrProtocol
	}
	if err := conn.SetDeadline(call.Deadline.Add(cancelWait)); err != nil {
		return Result{}, err
	}
	commandCtx, cancel := context.WithDeadline(ctx, call.Deadline)
	defer cancel()
	// On cancellation or deadline, half-close so the master cancels the
	// command, then wait briefly for its cleanup result. CloseWrite fails
	// when the master has already closed; its reply may still be buffered.
	// A connection that cannot half-close is closed, and the outcome stays
	// uncertain.
	stop := context.AfterFunc(commandCtx, func() {
		cw, ok := conn.(closeWriter)
		if !ok {
			_ = conn.Close()
			return
		}
		_ = cw.CloseWrite()
		_ = conn.SetDeadline(time.Now().Add(cancelWait))
	})
	defer stop()
	if err := writeJSONFrame(conn, frameRequest, call); err != nil {
		return Result{}, uncertainCommandError(commandCtx, call.Deadline, err)
	}
	for {
		kind, payload, err := readFrame(conn)
		if err != nil {
			return Result{}, uncertainCommandError(commandCtx, call.Deadline, err)
		}
		switch kind {
		case frameStdout, frameStderr:
			if commandCtx.Err() != nil {
				// Output after cancellation is dropped while waiting for
				// the cleanup result.
				continue
			}
			writer := stdout
			if kind == frameStderr {
				writer = stderr
			}
			type outputWrite struct {
				n   int
				err error
			}
			// Only one frame is pending while a writer is blocked. The CLI can
			// return at its deadline even if a caller's writer cannot be canceled.
			written := make(chan outputWrite, 1)
			go func() {
				n, err := writer.Write(payload)
				written <- outputWrite{n, err}
			}()
			var n int
			select {
			case outcome := <-written:
				n, err = outcome.n, outcome.err
			case <-commandCtx.Done():
				return Result{}, errors.Join(commandCtx.Err(), CategoryError{Category: CategoryRemoteStateUnknown})
			}
			if err != nil {
				return Result{}, errors.Join(err, CategoryError{Category: CategoryRemoteStateUnknown})
			}
			if n != len(payload) {
				return Result{}, errors.Join(io.ErrShortWrite, CategoryError{Category: CategoryRemoteStateUnknown})
			}
		case frameResult:
			var result Result
			if err := decodeStrictJSON(payload, &result); err != nil || result.ExitCode < 0 || uint64(result.ExitCode) > math.MaxUint32 || result.Category != "" && !validCategory(result.Category) {
				return Result{}, ErrProtocol
			}
			if result.Category == "" && commandCtx.Err() != nil {
				// The command finished, but output read after cancellation
				// was dropped. Never report that as success.
				return Result{}, commandCtx.Err()
			}
			return result, nil
		case frameError:
			category := string(payload)
			if !validCategory(category) {
				return Result{}, ErrProtocol
			}
			return Result{}, CategoryError{Category: category}
		default:
			return Result{}, ErrProtocol
		}
	}
}

func uncertainCommandError(ctx context.Context, deadline time.Time, err error) error {
	failure := transportCommandError(ctx, deadline, err)
	if errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded) {
		return errors.Join(failure, CategoryError{Category: CategoryRemoteStateUnknown})
	}
	return CategoryError{Category: CategoryRemoteStateUnknown}
}

func transportCommandError(ctx context.Context, deadline time.Time, err error) error {
	if !deadline.After(time.Now()) {
		return context.DeadlineExceeded
	}
	return transportError(ctx, err)
}

func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}
