package main

import (
	"context"
	"io"
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
