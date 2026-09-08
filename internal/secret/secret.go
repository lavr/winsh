// Package secret reads a password without accepting it in argv or persisting it.
package secret

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
)

func Read(env string, stdinMode bool, stdin io.Reader, lookup func(string) string) (string, error) {
	if !stdinMode {
		value := lookup(env)
		if value == "" {
			return "", errors.New("password environment variable is empty; set it or use --password-stdin")
		}
		return value, nil
	}
	reader := bufio.NewReaderSize(stdin, 65536)
	line, err := reader.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("cannot read password line (maximum 65535 bytes)")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	if value == "" {
		return "", errors.New("password line is empty")
	}
	return value, nil
}

// ReadContext permits cancellation even when the operating system cannot wake
// a blocked stdin read. The caller owns stdin and must close it (or exit the
// CLI process) after cancellation. At most one reader goroutine is created.
func ReadContext(ctx context.Context, env string, stdinMode bool, stdin io.Reader, lookup func(string) string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !stdinMode {
		return Read(env, false, stdin, lookup)
	}
	type result struct {
		value string
		err   error
	}
	// Buffer one result so a reader finishing after cancellation can terminate.
	results := make(chan result, 1)
	go func() { value, err := Read(env, true, stdin, lookup); results <- result{value, err} }()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-results:
		return result.value, result.err
	}
}
