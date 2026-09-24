package remote

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	winrm "github.com/masterzen/winrm"
)

// session is a WinRS shell that owns one running command. It exposes the
// WinRM Send/Receive surface as Go methods and runs the Receive poll loop
// in a background goroutine so callers can interleave SendInput calls
// with output draining on distinct authenticated HTTP exchanges.
//
// Lifecycle:
//
//	startSession -> shell opened, command started, receive loop running
//	send         -> one SendInput call (synchronous; serialized internally)
//	receive      -> blocks until the receive loop exits; returns rc / err
//	close        -> cancels the receive loop, waits for it to stop, then
//	                deletes the shell within the supplied cleanup context.
//
// All post() calls made by the session use a context tied to the session
// lifecycle so close() can unblock an orphaned Send or Receive that the
// caller forgot to cancel.
type session struct {
	endpoint  string
	shellID   string
	commandID string
	params    *winrm.Parameters
	p         poster
	cleanup   poster

	// Output destinations are set once by receive(); the receive loop
	// blocks on outReady until they are populated.
	outMu    sync.Mutex
	stdout   io.Writer
	stderr   io.Writer
	outSet   bool
	outReady chan struct{}

	// Lifecycle plumbing.
	cancel        context.CancelFunc
	recvDone      chan struct{}
	recvExit      int
	recvErr       error
	closed        atomic.Bool
	lifecycleDone chan struct{}

	// Serializes concurrent SendInput calls. Distinct SOAP exchanges are
	// allowed; what we forbid is two callers racing on the same shell.
	sendMu sync.Mutex
}

// startSession opens a WinRM shell, starts the given command, and spawns
// the receive loop. The command string is encoded exactly once via
// Command(); CDATA injection is prevented by the same escape used in
// run(). The supplied context bounds the Open and Execute SOAP calls;
// the receive loop runs under a derived context so close() can cancel
// it independently of the caller's deadline.
func startSession(ctx context.Context, r Request, p poster) (*session, error) {
	return startSessionWithCleanup(ctx, r, p, p)
}

func startSessionWithCleanup(ctx context.Context, r Request, p, cleanup poster) (*session, error) {
	command, err := Command(r.Command, r.PowerShell)
	if err != nil {
		return nil, err
	}
	command = strings.ReplaceAll(command, "]]>", "]]]]><![CDATA[>")
	params := winrm.NewParameters("PT30S", "en-US", 153600)

	s := &session{
		endpoint:      r.Endpoint,
		params:        params,
		p:             p,
		cleanup:       cleanup,
		outReady:      make(chan struct{}),
		recvDone:      make(chan struct{}),
		lifecycleDone: make(chan struct{}),
	}

	// Open shell. The pinned dependency hardcodes the WinRS output
	// codepage to 65001; we substitute the requested codepage (an
	// explicit allowlist of 866 / 1251) into the single matching marker
	// before posting. Failing closed if the marker is missing or appears
	// twice keeps us honest against upstream wire-shape changes.
	openMsg := winrm.NewOpenShellRequest(r.Endpoint, params)
	body := openMsg.String()
	if !r.PowerShell && (r.Codepage == "866" || r.Codepage == "1251") {
		const marker = `Name="WINRS_CODEPAGE">65001`
		if strings.Count(body, marker) != 1 {
			openMsg.Free()
			return nil, errors.New("cannot set WinRS codepage")
		}
		body = strings.Replace(body, marker, `Name="WINRS_CODEPAGE">`+r.Codepage, 1)
	}
	reply, err := p.post(ctx, body)
	openMsg.Free()
	if errors.Is(err, errUnsent) {
		return nil, notStarted(err)
	}
	if err != nil {
		return nil, errors.Join(err, ErrRemoteStateUnknown)
	}
	opened, err := parseResponse(reply)
	if err != nil {
		return nil, errors.Join(err, ErrRemoteStateUnknown)
	}
	if opened.Header.Action != wsTransfer+"CreateResponse" || !validID(opened.Body.Shell.ID) {
		return nil, errors.Join(errors.New("invalid WinRM shell response"), ErrRemoteStateUnknown)
	}
	s.shellID = opened.Body.Shell.ID

	// Execute command. On any failure from here on, best-effort delete
	// the shell we just opened so it is not leaked.
	execMsg := winrm.NewExecuteCommandRequest(r.Endpoint, s.shellID, command, nil, params)
	reply, err = p.post(ctx, execMsg.String())
	execMsg.Free()
	if err != nil {
		if s.deleteShellBestEffort() != nil {
			return nil, errors.Join(err, ErrRemoteStateUnknown)
		}
		return nil, err
	}
	started, err := parseResponse(reply)
	if err != nil {
		if s.deleteShellBestEffort() != nil {
			return nil, errors.Join(err, ErrRemoteStateUnknown)
		}
		return nil, err
	}
	if started.Header.Action != wsShell+"CommandResponse" || !validID(started.Body.Command.ID) {
		if s.deleteShellBestEffort() != nil {
			return nil, ErrRemoteStateUnknown
		}
		return nil, errors.New("invalid WinRM command response")
	}
	s.commandID = started.Body.Command.ID

	// Start receive loop under a cancellable derived context. close()
	// cancels this even if the caller's ctx is fine.
	innerCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.receiveLoop(innerCtx)
	return s, nil
}

// send issues one WSMan SendInput exchange with the given bytes and EOF
// flag. The bytes are passed verbatim to the library, which performs the
// SOAP-side Base64 encoding. send returns when the SendResponse action
// has been verified. Concurrent send calls are serialized; an in-flight
// send is also cancelled if close() runs. send re-checks the closed flag
// after acquiring the send mutex so it cannot race past an in-flight
// close that is waiting on the same mutex.
func (s *session) send(ctx context.Context, data []byte, eof bool) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed.Load() {
		return errors.New("session closed")
	}

	combined, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-s.lifecycleDone:
			cancel()
		case <-stop:
		}
	}()

	msg := winrm.NewSendInputRequest(s.endpoint, s.shellID, s.commandID, data, eof, s.params)
	defer msg.Free()
	reply, err := s.p.post(combined, msg.String())
	if err != nil {
		return err
	}
	resp, err := parseResponse(reply)
	if err != nil {
		return err
	}
	if resp.Header.Action != wsShell+"SendResponse" {
		return errors.New("invalid WinRM SendResponse")
	}
	return nil
}

// receive returns the command exit code and any error from the receive
// loop. It blocks until the loop exits (either the remote command is
// done, an error is reported, or the supplied context is cancelled).
// stdout and stderr are wired into the loop on first call; subsequent
// calls reuse the same writers and just observe the result. If the
// session was already closed when receive was called, the call waits
// for the receive loop to finish writing its result fields before
// returning them; this avoids a torn read of recvExit / recvErr.
func (s *session) receive(ctx context.Context, stdout, stderr io.Writer) (int, error) {
	if s.closed.Load() {
		select {
		case <-s.recvDone:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		return s.recvExit, s.recvErr
	}
	s.outMu.Lock()
	if !s.outSet {
		s.stdout = stdout
		s.stderr = stderr
		s.outSet = true
		close(s.outReady)
	}
	s.outMu.Unlock()

	select {
	case <-s.recvDone:
		return s.recvExit, s.recvErr
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// sendMessage is a raw escape hatch for sending a prebuilt SOAP body. It
// uses the session's lifecycle context so close() can cancel an
// in-flight message. Reserved for tests and unusual actions (e.g. an
// out-of-band Signal); transfers and run() go through send/receive.
func (s *session) sendMessage(body []byte) (string, error) {
	if s.closed.Load() {
		return "", errors.New("session closed")
	}
	combined, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-s.lifecycleDone:
			cancel()
		case <-stop:
		}
	}()
	return s.p.post(combined, string(body))
}

// close stops the receive loop and deletes the shell within the supplied
// context. The context's deadline is the caller's cleanup budget; close
// does not allocate its own timeout. It is safe to call close multiple
// times; subsequent calls wait for the receive loop and return nil.
//
// Ordering matters here: lifecycleDone is closed BEFORE sendMu is
// acquired, otherwise a SendInput blocked inside post() would hold the
// mutex forever and close would deadlock waiting for it. The lifecycle
// signal cancels the in-flight post via the per-send helper goroutine,
// the blocked send returns, releases sendMu, and close can proceed.
//
// Output pipes are aborted before joining the receive worker. Other writers
// must be unblocked by their owner; failure to join is reported within ctx's
// budget, never hidden behind a successful shell deletion.
func (s *session) close(ctx context.Context) error {
	return s.closeWith(ctx, s.p, s.p, false)
}

func (s *session) closeWith(ctx context.Context, primary, fallback poster, signal bool) error {
	if !s.closed.CompareAndSwap(false, true) {
		select {
		case <-s.recvDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	close(s.lifecycleDone)
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.cancel()
	s.outMu.Lock()
	for _, w := range []io.Writer{s.stdout, s.stderr} {
		if pipe, ok := w.(*io.PipeWriter); ok {
			_ = pipe.CloseWithError(context.Canceled)
		}
	}
	s.outMu.Unlock()
	var signalFailed bool
	deletePoster := primary
	if signal && s.commandID != "" {
		msg := winrm.NewSignalRequest(s.endpoint, s.shellID, s.commandID, s.params)
		reply, err := primary.post(ctx, msg.String())
		msg.Free()
		if err == nil {
			var resp response
			resp, err = parseResponse(reply)
			if err == nil && resp.Header.Action != wsShell+"SignalResponse" {
				err = errors.New("invalid WinRM SignalResponse")
			}
		}
		if err != nil {
			signalFailed = true
			deletePoster = fallback
		}
	}
	// Delete even if an arbitrary output writer is stuck; both teardown and
	// joining share the original cleanup deadline. A failed Signal uses the
	// independent cleanup lane for the distinct Delete request.
	msg := winrm.NewDeleteShellRequest(s.endpoint, s.shellID, s.params)
	defer msg.Free()
	reply, err := deletePoster.post(ctx, msg.String())
	if err == nil {
		var resp response
		resp, err = parseResponse(reply)
		if err == nil && resp.Header.Action != wsTransfer+"DeleteResponse" {
			err = errors.New("invalid WinRM DeleteResponse")
		}
	}
	select {
	case <-s.recvDone:
		if err != nil {
			return ErrRemoteStateUnknown
		}
		if signalFailed {
			return ErrCleanupFailed
		}
		return nil
	case <-ctx.Done():
		if err != nil {
			return errors.Join(ErrRemoteStateUnknown, ctx.Err())
		}
		return errors.Join(ErrCleanupFailed, ctx.Err())
	}
}

// receiveLoop polls WSMan GetOutput until the remote command is done, an
// error occurs, or the session context is cancelled. It writes decoded
// stdout / stderr to the writers set by receive().
func (s *session) receiveLoop(ctx context.Context) {
	defer close(s.recvDone)
	defer s.cancel()

	select {
	case <-s.outReady:
	case <-ctx.Done():
		s.recvErr = ctx.Err()
		return
	case <-s.lifecycleDone:
		s.recvErr = errors.New("session closed before output")
		return
	}
	s.outMu.Lock()
	stdout, stderr := s.stdout, s.stderr
	s.outMu.Unlock()

	for {
		if err := ctx.Err(); err != nil {
			s.recvErr = err
			return
		}
		msg := winrm.NewGetOutputRequest(s.endpoint, s.shellID, s.commandID, "stdout stderr", s.params)
		reply, err := s.p.post(ctx, msg.String())
		msg.Free()
		if errors.Is(err, errOperationTimeout) {
			continue
		}
		if err != nil {
			s.recvErr = err
			return
		}
		resp, err := parseResponse(reply)
		if errors.Is(err, errOperationTimeout) {
			continue
		}
		if err != nil {
			s.recvErr = err
			return
		}
		done, rc, err := resp.receive(stdout, stderr)
		if err != nil {
			s.recvErr = err
			return
		}
		if done {
			s.recvExit = rc
			return
		}
	}
}

// deleteShellBestEffort deletes the shell with a fresh five-second
// budget. Used by startSession when it cannot complete the bootstrap
// after the shell was already opened; the cleanup is best-effort and
// never blocks the original error.
func (s *session) deleteShellBestEffort() error {
	if s.shellID == "" {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := winrm.NewDeleteShellRequest(s.endpoint, s.shellID, s.params)
	defer msg.Free()
	reply, err := s.cleanup.post(cleanup, msg.String())
	if err != nil {
		return err
	}
	resp, err := parseResponse(reply)
	if err != nil || resp.Header.Action != wsTransfer+"DeleteResponse" {
		return errors.New("invalid WinRM DeleteResponse")
	}
	return nil
}
