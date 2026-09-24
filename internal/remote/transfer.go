package remote

import (
	"context"
	"errors"
)

// TransferDirection selects between upload (local -> remote) and download
// (remote -> local) for a single Transfer call.
type TransferDirection string

const (
	Upload   TransferDirection = "upload"
	Download TransferDirection = "download"
)

// TransferRequest is the input to Transfer. Connection carries the same
// fields as Run's Request; LocalPath and RemotePath are literal paths
// (no shell expansion or wildcards). Force selects whether an existing
// destination is replaced atomically; the default is refusal.
type TransferRequest struct {
	Connection            Request
	Direction             TransferDirection
	LocalPath, RemotePath string
	Force                 bool
}

// TransferResult is the output of a verified transfer. Bytes and SHA256
// describe the bytes that reached (or were committed to) the destination.
// Committed is true once the destination reflects the verified file; a
// post-commit cleanup failure does not flip it back. Artifacts lists any
// leftover stage / control paths the caller may want to clean up. It
// never contains file contents or credentials.
type TransferResult struct {
	Bytes     int64
	SHA256    string
	Committed bool
	Artifacts []string
}

// FinalizationUnknownError is returned when the commit command may have
// been delivered to the remote but its completion result is unavailable.
// The destination may contain either the previous file or the verified
// replacement; the caller must not assume either. Cause carries the
// underlying transport / timeout / cancellation error so callers can
// classify it via errors.Is.
type FinalizationUnknownError struct{ Cause error }

func (e *FinalizationUnknownError) Error() string {
	return "finalization outcome unknown"
}

func (e *FinalizationUnknownError) Unwrap() error { return e.Cause }

// RemoteExitError is returned when the remote script / command exited
// non-zero with a parseable exit code. Code follows run/ps conventions.
type RemoteExitError struct{ Code int }

func (e *RemoteExitError) Error() string {
	return "remote command exited with non-zero status"
}

// TransferInputError is returned for validation failures that the CLI maps
// to exit status 201. Message is restricted to fixed validation
// diagnostics; never include file contents, paths beyond their
// validated form, or credentials.
type TransferInputError struct{ Message string }

func (e *TransferInputError) Error() string { return e.Message }

// IsTransferInputError reports whether err is (or wraps) a
// TransferInputError. The CLI uses this to map validation failures to
// status 201.
func IsTransferInputError(err error) bool {
	var t *TransferInputError
	return errors.As(err, &t)
}

// Transfer sends a single regular file through the existing WinRM transport.
func Transfer(ctx context.Context, req TransferRequest, progress func(int64)) (TransferResult, error) {
	return transfer(ctx, req, progress, newTransport(req.Connection))
}

func transfer(ctx context.Context, req TransferRequest, progress func(int64), p poster) (TransferResult, error) {
	if req.Direction != Upload && req.Direction != Download {
		return TransferResult{}, &TransferInputError{Message: "transfer direction must be upload or download"}
	}
	if req.LocalPath == "" || req.RemotePath == "" || req.LocalPath == "-" || req.RemotePath == "-" {
		return TransferResult{}, &TransferInputError{Message: "transfer requires two file paths"}
	}
	if err := validateRemotePath(req.RemotePath); err != nil {
		return TransferResult{}, &TransferInputError{Message: err.Error()}
	}
	if progress == nil {
		progress = func(int64) {}
	}
	if req.Direction == Upload {
		return upload(ctx, req, progress, p)
	}
	return download(ctx, req, progress, p)
}
