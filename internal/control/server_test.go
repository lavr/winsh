//go:build linux || darwin

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lavr/winsh/internal/remote"
)

type dispatchPoster func(context.Context, string) (string, error)

func (p dispatchPoster) Post(ctx context.Context, body string) (string, error) { return p(ctx, body) }

const testShellURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
const testTransferURI = "http://schemas.xmlsoap.org/ws/2004/09/transfer/"

func dispatchEnvelope(action, body string) string {
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>` + action + `</a:Action></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
}

func dispatchFixture(t *testing.T, execute func(context.Context, Call, io.Writer, io.Writer) (int, error)) (*masterServer, string) {
	t.Helper()
	return dispatchFixtureWith(t, execute, nil)
}

func dispatchFixtureWith(t *testing.T, execute func(context.Context, Call, io.Writer, io.Writer) (int, error), configure func(*masterServer)) (*masterServer, string) {
	t.Helper()
	path := filepath.Join(shortControlDir(t), "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	server := newMasterServer(ctx, listener, testIdentity(), time.Second, execute)
	if configure != nil {
		configure(server)
	}
	done := make(chan error, 1)
	go func() { done <- server.serve() }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("master server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("master server did not stop")
		}
	})
	return server, path
}

func testCall(deadline time.Time) Call {
	return Call{Identity: testIdentity(), Command: "hostname", Deadline: deadline, Persist: time.Second}
}

func waitQueue(t *testing.T, server *masterServer, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		got := len(server.queue)
		server.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queue did not reach %d", want)
}

func TestMasterDispatchQueueAndExit(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var executions atomic.Int32
	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32
	server, path := dispatchFixture(t, func(ctx context.Context, call Call, stdout, stderr io.Writer) (int, error) {
		executions.Add(1)
		current := concurrent.Add(1)
		if current > maxConcurrent.Load() {
			maxConcurrent.Store(current)
		}
		defer concurrent.Add(-1)
		if current == 1 && executions.Load() == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		_, _ = io.WriteString(stdout, "ok")
		return 7, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := Invoke(ctx, path, testCall(time.Now().Add(3*time.Second)), io.Discard, io.Discard)
		first <- err
	}()
	<-started
	var wg sync.WaitGroup
	queuedResults := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := Invoke(ctx, path, testCall(time.Now().Add(3*time.Second)), io.Discard, io.Discard)
			if err == nil && result.Category != CategoryNotStarted {
				err = errors.New("queued command was not rejected as not-started")
			}
			queuedResults <- err
		}()
	}
	waitQueue(t, server, 16)
	_, err := Invoke(ctx, path, testCall(time.Now().Add(3*time.Second)), io.Discard, io.Discard)
	var category CategoryError
	if !errors.As(err, &category) || category.Category != CategoryQueueFull {
		t.Fatalf("17th waiter = %v", err)
	}
	exitDone := make(chan error, 1)
	go func() { exitDone <- Exit(ctx, path, testIdentity(), time.Second) }()
	waitQueue(t, server, 0)
	if executions.Load() != 1 {
		t.Fatal("exit dispatched a queued command")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-exitDone; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(queuedResults)
	for err := range queuedResults {
		if err != nil {
			t.Fatalf("queued exit result: %v", err)
		}
	}
	if maxConcurrent.Load() != 1 {
		t.Fatalf("executed %d commands concurrently", maxConcurrent.Load())
	}
}

func TestMasterDispatchQueueDeadlineDoesNotCancelActive(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var executed atomic.Int32
	server, path := dispatchFixture(t, func(ctx context.Context, _ Call, _, _ io.Writer) (int, error) {
		executed.Add(1)
		close(started)
		select {
		case <-release:
			return 0, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := Invoke(ctx, path, testCall(time.Now().Add(2*time.Second)), io.Discard, io.Discard)
		first <- err
	}()
	<-started
	_, err := Invoke(ctx, path, testCall(time.Now().Add(50*time.Millisecond)), io.Discard, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued deadline = %v", err)
	}
	waitQueue(t, server, 0)
	if executed.Load() != 1 {
		t.Fatal("expired waiter dispatched")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestMasterDispatchClientDisconnectStopsAdmission(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	var executed atomic.Int32
	_, path := dispatchFixture(t, func(ctx context.Context, _ Call, _, _ io.Writer) (int, error) {
		executed.Add(1)
		close(started)
		<-ctx.Done()
		close(finished)
		return 0, ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := Invoke(ctx, path, testCall(time.Now().Add(2*time.Second)), io.Discard, io.Discard)
		result <- err
	}()
	<-started
	cancel()
	<-result
	<-finished
	time.Sleep(20 * time.Millisecond)
	if executed.Load() != 1 {
		t.Fatalf("uncertain command replayed: %d executions", executed.Load())
	}
}

func TestMasterDispatchDisconnectCleansKnownRemoteIDs(t *testing.T) {
	dispatched := make(chan struct{})
	cleaned := make(chan struct{})
	var commands atomic.Int32
	command := dispatchPoster(func(ctx context.Context, body string) (string, error) {
		switch {
		case strings.Contains(body, testTransferURI+"Create"):
			return dispatchEnvelope(testTransferURI+"CreateResponse", `<rsp:Shell><rsp:ShellId>shell-1</rsp:ShellId></rsp:Shell>`), nil
		case strings.Contains(body, testShellURI+"Command"):
			commands.Add(1)
			close(dispatched)
			return dispatchEnvelope(testShellURI+"CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command-1</rsp:CommandId></rsp:CommandResponse>`), nil
		case strings.Contains(body, testShellURI+"Send"):
			return dispatchEnvelope(testShellURI+"SendResponse", ""), nil
		case strings.Contains(body, testShellURI+"Receive"):
			<-ctx.Done()
			return "", ctx.Err()
		default:
			return "", errors.New("command lane used after disconnect")
		}
	})
	var cleanupActions []string
	var cleanupMu sync.Mutex
	cleanup := dispatchPoster(func(_ context.Context, body string) (string, error) {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		switch {
		case strings.Contains(body, testShellURI+"Signal"):
			if !strings.Contains(body, "shell-1") || !strings.Contains(body, "command-1") {
				return "", errors.New("wrong cleanup IDs")
			}
			cleanupActions = append(cleanupActions, "signal")
			return dispatchEnvelope(testShellURI+"SignalResponse", ""), nil
		case strings.Contains(body, testTransferURI+"Delete"):
			cleanupActions = append(cleanupActions, "delete")
			close(cleaned)
			return dispatchEnvelope(testTransferURI+"DeleteResponse", ""), nil
		default:
			return "", errors.New("unexpected cleanup action")
		}
	})
	_, path := dispatchFixture(t, func(ctx context.Context, call Call, stdout, stderr io.Writer) (int, error) {
		r := remote.Request{Endpoint: call.Identity.Endpoint, Command: call.Command}
		return remote.RunWithPosters(ctx, r, stdout, stderr, command, cleanup)
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := Invoke(ctx, path, testCall(time.Now().Add(2*time.Second)), io.Discard, io.Discard)
		result <- err
	}()
	<-dispatched
	cancel()
	<-result
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("known Shell/Command IDs were not cleaned")
	}
	cleanupMu.Lock()
	actions := append([]string(nil), cleanupActions...)
	cleanupMu.Unlock()
	if len(actions) != 2 || actions[0] != "signal" || actions[1] != "delete" || commands.Load() != 1 {
		t.Fatalf("cleanup=%v dispatched=%d", actions, commands.Load())
	}
}

func waitStopped(t *testing.T, server *masterServer) {
	t.Helper()
	select {
	case <-server.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("master did not stop")
	}
}

func TestMasterHeartbeatFailureStopsIdleMaster(t *testing.T) {
	var beats atomic.Int32
	server, path := dispatchFixtureWith(t, func(context.Context, Call, io.Writer, io.Writer) (int, error) {
		t.Error("executed a command after heartbeat failure")
		return 0, nil
	}, func(s *masterServer) {
		s.heartbeatEvery = 10 * time.Millisecond
		s.heartbeat = func(context.Context) error {
			if beats.Add(1) < 3 {
				return nil
			}
			return errors.New("lane closed")
		}
	})
	waitStopped(t, server)
	if _, err := Invoke(t.Context(), path, testCall(time.Now().Add(time.Second)), io.Discard, io.Discard); err == nil {
		t.Fatal("stopped master accepted a command")
	}
	if beats.Load() != 3 {
		t.Fatalf("heartbeat continued after failure: %d beats", beats.Load())
	}
}

func TestMasterHeartbeatFailureLetsActiveCommandFinish(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	failed := make(chan struct{})
	var once sync.Once
	server, path := dispatchFixtureWith(t, func(ctx context.Context, call Call, stdout, stderr io.Writer) (int, error) {
		close(started)
		<-release
		_, _ = io.WriteString(stdout, "ok")
		return 7, nil
	}, func(s *masterServer) {
		s.heartbeatEvery = 10 * time.Millisecond
		s.heartbeat = func(context.Context) error {
			select {
			case <-started:
				once.Do(func() { close(failed) })
				return errors.New("cleanup lane closed")
			default:
				return nil
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	first := make(chan Result, 1)
	go func() {
		result, err := Invoke(ctx, path, testCall(time.Now().Add(2*time.Second)), io.Discard, io.Discard)
		if err != nil {
			t.Error(err)
		}
		first <- result
	}()
	<-started
	queued := make(chan Result, 1)
	go func() {
		result, err := Invoke(ctx, path, testCall(time.Now().Add(2*time.Second)), io.Discard, io.Discard)
		if err != nil {
			t.Error(err)
		}
		queued <- result
	}()
	<-failed
	if result := <-queued; result.Category != CategoryNotStarted {
		t.Fatalf("queued command after heartbeat failure = %+v", result)
	}
	select {
	case <-server.stopped:
		t.Fatal("master stopped before the active command finished")
	default:
	}
	close(release)
	if result := <-first; result.Category != "" || result.ExitCode != 7 {
		t.Fatalf("active command result = %+v", result)
	}
	waitStopped(t, server)
}

func TestCategoryFromNotStarted(t *testing.T) {
	err := fmt.Errorf("create: %w", remote.ErrNotStarted)
	if got := categoryFromError(err); got != CategoryNotStarted {
		t.Fatalf("category = %q", got)
	}
	if got := categoryFromError(errors.Join(err, remote.ErrRemoteStateUnknown)); got != CategoryRemoteStateUnknown {
		t.Fatalf("unknown state lost priority: %q", got)
	}
}
