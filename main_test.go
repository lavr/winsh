package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"
)

type readyReader struct {
	*io.PipeReader
	ready chan struct{}
}

func (r readyReader) Read(p []byte) (int, error) {
	select {
	case <-r.ready:
	default:
		close(r.ready)
	}
	return r.PipeReader.Read(p)
}

func TestCancelDuringPasswordRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	rd, wr := io.Pipe()
	defer rd.Close()
	defer wr.Close()
	input := readyReader{rd, make(chan struct{})}
	result := make(chan int, 1)
	go func() {
		result <- runCLI(ctx, []string{"run", "server.example.com", "--user", "alice", "--password-stdin", "--", "hostname"}, input, io.Discard, io.Discard)
	}()
	<-input.ready
	cancel()
	select {
	case rc := <-result:
		if rc != 204 {
			t.Fatalf("rc=%d; want cancellation", rc)
		}
	case <-time.After(time.Second):
		t.Fatal("password read ignored cancellation")
	}
}

func TestProcessInterruptPassword(t *testing.T) {
	if os.Getenv("WINSH_TEST_SIGNAL_CHILD") == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		fmt.Println("ready")
		rc := runCLI(ctx, []string{"run", "server.example.com", "--user", "alice", "--password-stdin", "--", "hostname"}, os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(rc)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestProcessInterruptPassword$")
	child.Env = append(os.Environ(), "WINSH_TEST_SIGNAL_CHILD=1")
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	if _, err := bufio.NewReader(output).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// Allow the child to enter the real file read after installing its signal handler.
	time.Sleep(100 * time.Millisecond)
	if err := child.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	if ctx.Err() != nil {
		t.Fatal("SIGINT did not cancel reading real stdin pipe")
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 204 {
		t.Fatalf("exit=%v; expected 204", err)
	}
}
