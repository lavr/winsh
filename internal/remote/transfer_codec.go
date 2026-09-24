package remote

// Bounded transfer records, Base64 line framing, and request validation.
// The control record is a versioned, strict JSON document with duplicate-
// and unknown-key rejection. Base64 framing reads CRLF-terminated lines
// from a streaming source into a destination writer, never buffering more
// than maxLine+CRLF bytes per line. Path validation applies Windows rules
// to the remote operand regardless of the client's GOOS.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// transferRecord is the versioned metadata record emitted by the remote
// sender after it streams the source bytes. The schema is small and
// strictly checked: Version 1, ID, Bytes, SHA256. Unknown or duplicated
// keys are rejected.
type transferRecord struct {
	Version int    `json:"-"`
	ID      string `json:"-"`
	Bytes   int64  `json:"-"`
	SHA256  string `json:"-"`
}

// boundedOutput rejects a control stream before it can grow beyond its
// protocol limit. It never includes rejected bytes in error messages.
type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("transfer control output exceeds limit")
	}
	return b.Buffer.Write(p)
}

const (
	transferRecordVersion = 1
	transferRecordMaxSize = 4096
)

// readRecord parses one versioned control record from r and verifies it
// matches expectedID. The body must be a single JSON object no larger
// than transferRecordMaxSize bytes. All four schema fields
// (version, id, bytes, sha256) are required; duplicate keys and unknown
// keys are rejected. No data may follow the closing brace: the body is
// exactly one JSON object, nothing else.
func readRecord(r io.Reader, expectedID string) (transferRecord, error) {
	var rec transferRecord
	body, err := io.ReadAll(io.LimitReader(r, transferRecordMaxSize+1))
	if err != nil {
		return rec, fmt.Errorf("record read: %w", err)
	}
	if len(body) > transferRecordMaxSize {
		return rec, errors.New("record exceeds maximum size")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return rec, fmt.Errorf("record: %w", err)
	}
	if tok != json.Delim('{') {
		return rec, errors.New("record: expected JSON object")
	}
	required := map[string]bool{
		"version": false,
		"id":      false,
		"bytes":   false,
		"sha256":  false,
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return rec, fmt.Errorf("record key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return rec, errors.New("record: keys must be strings")
		}
		if _, isRequired := required[key]; !isRequired {
			return rec, fmt.Errorf("record: unknown key %q", key)
		}
		if required[key] {
			return rec, fmt.Errorf("record: duplicate key %q", key)
		}
		required[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return rec, fmt.Errorf("record %q value: %w", key, err)
		}
		switch key {
		case "version":
			var n json.Number
			if err := json.Unmarshal(raw, &n); err != nil {
				return rec, errors.New("record: version must be a number")
			}
			i, err := n.Int64()
			if err != nil || i < 0 || i > 1<<31-1 {
				return rec, errors.New("record: version out of range")
			}
			rec.Version = int(i)
		case "id":
			if err := json.Unmarshal(raw, &rec.ID); err != nil {
				return rec, errors.New("record: id must be a string")
			}
		case "bytes":
			n, err := parseInt64(raw)
			if err != nil {
				return rec, fmt.Errorf("record: bytes: %w", err)
			}
			rec.Bytes = n
		case "sha256":
			if err := json.Unmarshal(raw, &rec.SHA256); err != nil {
				return rec, errors.New("record: sha256 must be a string")
			}
		}
	}
	// Closing brace.
	if _, err := dec.Token(); err != nil {
		return rec, fmt.Errorf("record close: %w", err)
	}
	// Reject trailing data: the body is exactly one JSON object. After
	// the closing brace, no further tokens may remain in the stream.
	if _, err := dec.Token(); err == nil {
		return rec, errors.New("record: trailing data after JSON object")
	} else if !errors.Is(err, io.EOF) {
		return rec, fmt.Errorf("record: trailing data: %w", err)
	}
	for key, present := range required {
		if !present {
			return rec, fmt.Errorf("record: missing required key %q", key)
		}
	}
	if rec.Version != transferRecordVersion {
		return rec, fmt.Errorf("record: unsupported version %d", rec.Version)
	}
	if rec.ID != expectedID {
		return rec, fmt.Errorf("record: id mismatch got %q want %q", rec.ID, expectedID)
	}
	if rec.Bytes < 0 {
		return rec, errors.New("record: bytes must be non-negative")
	}
	if len(rec.SHA256) != 64 {
		return rec, fmt.Errorf("record: sha256 must be 64 chars, got %d", len(rec.SHA256))
	}
	for i := 0; i < len(rec.SHA256); i++ {
		c := rec.SHA256[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return rec, errors.New("record: sha256 must be lowercase hex")
		}
	}
	return rec, nil
}

// parseInt64 decodes a JSON number as int64, rejecting floats and
// out-of-range values.
func parseInt64(raw json.RawMessage) (int64, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errors.New("must be a number")
	}
	i, err := n.Int64()
	if err != nil {
		return 0, errors.New("must be an integer")
	}
	return i, nil
}

// copyBase64Lines reads CRLF-terminated Base64 lines from src, decodes
// each, writes the raw bytes to dst, and returns the total decoded byte
// count. Lines longer than maxLine without CRLF are rejected; the final
// line must terminate with CRLF; empty lines between data lines are
// tolerated (they decode to zero bytes). The function never buffers more
// than maxLine+CRLF bytes per line.
func copyBase64Lines(dst io.Writer, src io.Reader, maxLine int) (int64, error) {
	if maxLine <= 0 {
		return 0, errors.New("maxLine must be positive")
	}
	var total int64
	scanner := bufio.NewScanner(src)
	// Allow a small carry-over for the trailing CRLF; the scanner errors if
	// a line exceeds maxLine+1 bytes.
	scanner.Buffer(make([]byte, 64), maxLine+2)
	scanner.Split(splitCRLFLines(maxLine))
	for scanner.Scan() {
		decoded, err := base64.StdEncoding.DecodeString(string(scanner.Bytes()))
		if err != nil {
			return total, fmt.Errorf("invalid base64: %w", err)
		}
		if len(decoded) > 0 {
			if err := writeAll(dst, decoded); err != nil {
				return total, err
			}
		}
		total += int64(len(decoded))
	}
	if err := scanner.Err(); err != nil {
		return total, err
	}
	return total, nil
}

// writeAll writes all bytes to w, retrying on io.ErrShortWrite until the
// buffer is empty or a non-short-write error is reported. n must be > 0
// when err is nil (io.Writer contract); a violating writer is reported
// as io.ErrNoProgress so the caller does not spin.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err == nil {
			if len(p) > 0 {
				return io.ErrNoProgress
			}
			return nil
		}
		if n == 0 || !errors.Is(err, io.ErrShortWrite) {
			return err
		}
	}
	return nil
}

// splitCRLFLines returns a SplitFunc that emits one token per CRLF-
// terminated line. maxLine is the strict upper bound on line content (the
// trailing CRLF is not counted). It rejects stray \r without \n, lines
// that exceed maxLine without CRLF, and a missing terminal CRLF at EOF.
func splitCRLFLines(maxLine int) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (int, []byte, error) {
		for i := 0; i < len(data); i++ {
			if data[i] == '\r' {
				if i+1 < len(data) {
					if data[i+1] == '\n' {
						if i > maxLine {
							return 0, nil, errors.New("base64 line exceeds maximum length")
						}
						return i + 2, data[:i], nil
					}
					return 0, nil, errors.New("stray \\r without \\n")
				}
				// \r at end of buffer
				if !atEOF {
					return 0, nil, nil
				}
				return 0, nil, errors.New("stray \\r without \\n at EOF")
			}
		}
		if atEOF {
			if len(data) == 0 {
				return 0, nil, nil
			}
			if len(data) > maxLine {
				return 0, nil, errors.New("base64 line exceeds maximum length without CRLF")
			}
			return 0, nil, errors.New("missing terminal CRLF on last base64 line")
		}
		if len(data) > maxLine {
			return 0, nil, errors.New("base64 line exceeds maximum length without CRLF")
		}
		return 0, nil, nil
	}
}

// chunkSize returns the largest raw chunk size n such that builder(n)
// produces at most maxEnvelope bytes. Binary-searches monotonically. The
// builder must encode the chunk as it would appear on the wire (XML
// envelope + outer Base64 + inner Base64 line + CRLF). If no positive
// chunk size fits within the envelope, chunkSize returns an error
// rather than a value the caller cannot actually use.
func chunkSize(maxEnvelope int, builder func([]byte) (string, error)) (int, error) {
	if maxEnvelope <= 0 {
		return 0, errors.New("envelope must be positive")
	}
	if builder == nil {
		return 0, errors.New("builder required")
	}
	if _, err := builder(nil); err != nil {
		return 0, fmt.Errorf("builder empty: %w", err)
	}
	// Verify that at least one byte fits. If not, no chunk size is
	// usable; bail out before entering the search.
	if s, err := builder(make([]byte, 1)); err != nil {
		return 0, fmt.Errorf("builder(1): %w", err)
	} else if len(s) > maxEnvelope {
		return 0, fmt.Errorf("envelope %d too small for any chunk (1 byte encodes to %d)", maxEnvelope, len(s))
	}
	lo, hi := 1, maxEnvelope
	for lo < hi {
		mid := (lo + hi + 1) / 2
		s, err := builder(make([]byte, mid))
		if err != nil {
			return 0, fmt.Errorf("builder(%d): %w", mid, err)
		}
		if len(s) <= maxEnvelope {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo, nil
}

// reservedDeviceNames is the Windows set of filename-only reserved names
// that must be rejected as path components.
var reservedDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
	"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// validateRemotePath checks that p is a syntactically valid Windows
// filesystem path that winsh is willing to operate on. It enforces drive-
// rooted form, rejects UNC/device/relative/ADS/wildcard/reserved-name
// inputs and ambiguous trailing separators, but does not probe the
// filesystem for reparse points or other attributes (Tasks 5/6 do that
// separately with attribute-based checks).
//
// The function applies Windows path rules to the remote operand on both
// Linux and macOS clients.
func validateRemotePath(p string) error {
	if p == "" {
		return errors.New("remote path must not be empty")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("remote path must not contain NUL")
	}
	if strings.HasPrefix(p, `\\`) {
		return errors.New("remote path must not be UNC or device form")
	}
	if len(p) < 3 {
		return errors.New("remote path must be drive-rooted")
	}
	c := p[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return errors.New("remote path must start with a drive letter")
	}
	if p[1] != ':' {
		return errors.New("remote path must use drive form 'X:'")
	}
	if p[2] != '\\' && p[2] != '/' {
		return errors.New("remote path must use 'X:\\' or 'X:/'")
	}
	parts := strings.FieldsFunc(p[3:], func(r rune) bool {
		return r == '\\' || r == '/'
	})
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("remote path must not contain empty or relative components")
		}
		if strings.ContainsRune(part, ':') {
			return errors.New("remote path must not contain alternate data streams")
		}
		if strings.ContainsAny(part, `*?<>|"`) {
			return errors.New("remote path contains a forbidden Windows character")
		}
		if part != strings.TrimRight(part, " .") {
			return errors.New("remote path must not end with space or dot")
		}
		if isReservedStem(part) {
			return fmt.Errorf("remote path must not use reserved device name %q", part)
		}
	}
	return nil
}

// isReservedStem reports whether the Windows-reserved device name appears
// as either the full component or the stem before its extension. NTFS
// rejects paths like C:\PRN.txt because the stem before the extension is
// a reserved name.
func isReservedStem(component string) bool {
	upper := strings.ToUpper(component)
	if reservedDeviceNames[upper] {
		return true
	}
	if i := strings.Index(upper, "."); i > 0 {
		if reservedDeviceNames[upper[:i]] {
			return true
		}
	}
	return false
}
