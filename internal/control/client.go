package control

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"time"
)

// Invoke sends one command to a local master and streams output frames to the
// caller's writers. Closing the connection cancels only this command.
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
	if err := conn.SetDeadline(call.Deadline); err != nil {
		return Result{}, err
	}
	commandCtx, cancel := context.WithDeadline(ctx, call.Deadline)
	defer cancel()
	stop := context.AfterFunc(commandCtx, func() { _ = conn.Close() })
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
