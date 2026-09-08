package secret

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

type LookupEnv func(string) (string, bool)

// Resolve interprets exactly one prefix. Decoded and literal values are never
// recursively expanded, and failure messages never contain input values.
func Resolve(value string, lookup LookupEnv) (string, error) {
	switch {
	case strings.HasPrefix(value, "literal:"):
		value = strings.TrimPrefix(value, "literal:")
	case strings.HasPrefix(value, "env:"):
		name := strings.TrimPrefix(value, "env:")
		if name == "" || strings.ContainsAny(name, "=\x00\r\n") {
			return "", errors.New("invalid environment variable reference")
		}
		var ok bool
		value, ok = lookup(name)
		if !ok {
			return "", errors.New("credential environment variable is not set")
		}
	case strings.HasPrefix(value, "base64:"):
		decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(value, "base64:"))
		if err != nil {
			return "", errors.New("invalid base64 credential")
		}
		value = string(decoded)
	}
	if value == "" {
		return "", errors.New("credential value is empty")
	}
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return "", errors.New("credential value must be UTF-8 without NUL")
	}
	return value, nil
}
