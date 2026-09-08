package main

import (
	"context"
	"io"
	"os"
	"os/signal"

	"github.com/lavr/winsh/internal/cmd"
	"github.com/lavr/winsh/internal/remote"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, stdin io.ReadCloser, stdout, stderr io.Writer) int {
	// The process owns stdin. Closing it wakes a password read on cancellation.
	stopInput := context.AfterFunc(ctx, func() { _ = stdin.Close() })
	defer stopInput()
	return cmd.Run(ctx, args, cmd.Deps{Stdin: stdin, Stdout: stdout, Stderr: stderr, Getenv: os.Getenv, Execute: remote.Run, Version: version})
}
