// Package secret reads a password without accepting it in argv or persisting it.
package secret

import (
	"bufio"
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
