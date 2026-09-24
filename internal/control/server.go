//go:build linux || darwin

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lavr/winsh/internal/remote"
)

type commandExecutor func(context.Context, Call, io.Writer, io.Writer) (int, error)

type commandJob struct {
	call   Call
	ctx    context.Context
	cancel context.CancelFunc
	conn   net.Conn
	done   chan struct{}
	result Result
}

type masterServer struct {
	ctx      context.Context
	listener net.Listener
	identity Identity
	persist  time.Duration
	execute  commandExecutor

	mu      sync.Mutex
	active  *commandJob
	queue   []*commandJob
	exiting bool
	stopped chan struct{}
	idle    *time.Timer
	clients sync.WaitGroup
	workers sync.WaitGroup
}

func newMasterServer(ctx context.Context, listener net.Listener, identity Identity, persist time.Duration, execute commandExecutor) *masterServer {
	s := &masterServer{ctx: ctx, listener: listener, identity: identity, persist: persist, execute: execute, stopped: make(chan struct{})}
	s.idle = time.AfterFunc(persist, s.stopIfIdle)
	return s
}

func (s *masterServer) stopIfIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil && len(s.queue) == 0 {
		s.shutdownLocked()
	}
}

func (s *masterServer) shutdownLocked() {
	if s.exiting {
		select {
		case <-s.stopped:
			return
		default:
		}
	}
	s.exiting = true
	s.idle.Stop()
	_ = s.listener.Close()
	close(s.stopped)
}

func (s *masterServer) rejectQueueLocked() {
	for _, job := range s.queue {
		job.result = Result{Category: CategoryNotStarted}
		close(job.done)
	}
	s.queue = nil
}

func (s *masterServer) serve() error {
	stop := context.AfterFunc(s.ctx, func() {
		s.mu.Lock()
		s.rejectQueueLocked()
		s.shutdownLocked()
		s.mu.Unlock()
	})
	defer stop()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			s.rejectQueueLocked()
			s.shutdownLocked()
			s.mu.Unlock()
			s.workers.Wait()
			s.clients.Wait()
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return nil
			}
			return errors.New("control listener failed")
		}
		s.clients.Add(1)
		go func() {
			defer s.clients.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *masterServer) handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, payload, err := readFrame(conn)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	switch kind {
	case frameCheck, frameExit:
		var target controlTarget
		if decodeStrictJSON(payload, &target) != nil {
			_ = writeFrame(conn, frameError, []byte(CategoryNotStarted))
			return
		}
		result := s.checkTarget(target)
		if result.Category != "" || kind == frameCheck {
			_ = writeJSONFrame(conn, frameResult, result)
			return
		}
		s.mu.Lock()
		s.exiting = true
		s.rejectQueueLocked()
		if s.active == nil {
			s.shutdownLocked()
		}
		s.mu.Unlock()
		<-s.stopped
		_ = writeJSONFrame(conn, frameResult, Result{})
	case frameRequest:
		var call Call
		if decodeStrictJSON(payload, &call) != nil || validateCall(call) != nil {
			_ = writeFrame(conn, frameError, []byte(CategoryNotStarted))
			return
		}
		if result := s.checkTarget(controlTarget{Identity: call.Identity, Persist: call.Persist}); result.Category != "" {
			_ = writeJSONFrame(conn, frameResult, result)
			return
		}
		if !call.Deadline.After(time.Now()) {
			_ = writeJSONFrame(conn, frameResult, Result{Category: CategoryTimeout})
			return
		}
		_ = conn.SetDeadline(call.Deadline)
		jobCtx, cancel := context.WithDeadline(s.ctx, call.Deadline)
		job := &commandJob{call: call, ctx: jobCtx, cancel: cancel, conn: conn, done: make(chan struct{})}
		defer cancel()
		go func() {
			var b [1]byte
			_, _ = conn.Read(b[:])
			cancel()
		}()
		if category := s.enqueue(job); category != "" {
			_ = writeFrame(conn, frameError, []byte(category))
			return
		}
		select {
		case <-job.done:
			_ = writeJSONFrame(conn, frameResult, job.result)
		case <-jobCtx.Done():
			s.cancelQueued(job)
		}
	default:
		_ = writeFrame(conn, frameError, []byte(CategoryNotStarted))
	}
}

func (s *masterServer) checkTarget(target controlTarget) Result {
	s.mu.Lock()
	exiting := s.exiting
	s.mu.Unlock()
	if exiting {
		return Result{Category: CategoryUnavailable}
	}
	if !s.identity.sameTarget(target.Identity) {
		return Result{Category: CategoryIdentityMismatch}
	}
	if s.persist != target.Persist {
		return Result{Category: CategoryPersistMismatch}
	}
	return Result{}
}

func (s *masterServer) enqueue(job *commandJob) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exiting {
		return CategoryNotStarted
	}
	if job.ctx.Err() != nil {
		return CategoryTimeout
	}
	s.idle.Stop()
	if s.active == nil {
		s.active = job
		s.workers.Add(1)
		go s.run(job)
		return ""
	}
	if len(s.queue) >= 16 {
		return CategoryQueueFull
	}
	s.queue = append(s.queue, job)
	return ""
}

func (s *masterServer) cancelQueued(job *commandJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, queued := range s.queue {
		if queued == job {
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			job.result = Result{Category: categoryFromError(job.ctx.Err())}
			close(job.done)
			if s.active == nil && len(s.queue) == 0 && !s.exiting {
				s.idle.Reset(s.persist)
			}
			return
		}
	}
}

type framedWriter struct {
	conn   net.Conn
	kind   frameType
	mu     *sync.Mutex
	cancel context.CancelFunc
}

func (w framedWriter) Write(data []byte) (int, error) {
	length := len(data)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > int(maxFramePayload) {
			chunk = chunk[:maxFramePayload]
		}
		w.mu.Lock()
		err := writeFrame(w.conn, w.kind, chunk)
		w.mu.Unlock()
		if err != nil {
			w.cancel()
			return length - len(data), err
		}
		data = data[len(chunk):]
	}
	return length, nil
}

func (s *masterServer) run(job *commandJob) {
	defer s.workers.Done()
	result := Result{}
	terminal := false
	if err := job.ctx.Err(); err != nil {
		result.Category = categoryFromError(err)
	} else if !s.identity.sameTarget(job.call.Identity) {
		result.Category = CategoryIdentityMismatch
	} else {
		var writeMu sync.Mutex
		stdout := framedWriter{conn: job.conn, kind: frameStdout, mu: &writeMu, cancel: job.cancel}
		stderr := framedWriter{conn: job.conn, kind: frameStderr, mu: &writeMu, cancel: job.cancel}
		rc, err := s.execute(job.ctx, job.call, stdout, stderr)
		result.ExitCode = rc
		if err != nil {
			result.Category = categoryFromError(err)
			terminal = true
		}
	}
	s.mu.Lock()
	job.result = result
	close(job.done)
	s.active = nil
	if terminal {
		s.exiting = true
	}
	if s.exiting {
		s.rejectQueueLocked()
		s.shutdownLocked()
	} else {
		for len(s.queue) > 0 {
			next := s.queue[0]
			s.queue = s.queue[1:]
			if err := next.ctx.Err(); err != nil {
				next.result = Result{Category: categoryFromError(err)}
				close(next.done)
				continue
			}
			s.active = next
			s.workers.Add(1)
			go s.run(next)
			break
		}
		if s.active == nil {
			s.idle.Reset(s.persist)
		}
	}
	s.mu.Unlock()
}

func categoryFromError(err error) string {
	switch {
	case errors.Is(err, remote.ErrRemoteStateUnknown):
		return CategoryRemoteStateUnknown
	case errors.Is(err, remote.ErrCleanupFailed):
		return CategoryCleanupFailed
	case errors.Is(err, context.DeadlineExceeded):
		return CategoryTimeout
	case errors.Is(err, context.Canceled):
		return CategoryCanceled
	default:
		return CategoryUnavailable
	}
}
