package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const protocolVersion byte = 1
const maxFramePayload uint32 = 64 * 1024

var ErrProtocol = errors.New("invalid local control protocol")

type frameType byte

const (
	frameRequest frameType = iota + 1
	frameStdout
	frameStderr
	frameResult
	frameCheck
	frameExit
	frameError
)

type Call struct {
	Identity   Identity
	Command    string
	PowerShell bool
	Codepage   string
	Deadline   time.Time
	Persist    time.Duration
}

type Result struct {
	ExitCode int
	Category string
}

const (
	CategoryNotStarted         = "not-started"
	CategoryIdentityMismatch   = "identity-mismatch"
	CategoryPersistMismatch    = "persist-mismatch"
	CategoryQueueFull          = "queue-full"
	CategoryTimeout            = "timeout"
	CategoryCanceled           = "canceled"
	CategoryCleanupFailed      = "cleanup-failed"
	CategoryRemoteStateUnknown = "remote-state-unknown"
	CategoryUnavailable        = "unavailable"
)

type CategoryError struct{ Category string }

func (e CategoryError) Error() string { return "control: " + e.Category }

func validCategory(category string) bool {
	switch category {
	case CategoryNotStarted, CategoryIdentityMismatch, CategoryPersistMismatch,
		CategoryQueueFull, CategoryTimeout, CategoryCanceled, CategoryCleanupFailed,
		CategoryRemoteStateUnknown, CategoryUnavailable:
		return true
	}
	return false
}

func validFrameType(kind frameType) bool {
	return kind >= frameRequest && kind <= frameError
}

func writeFrame(w io.Writer, kind frameType, payload []byte) error {
	if !validFrameType(kind) || len(payload) > int(maxFramePayload) {
		return ErrProtocol
	}
	var header [6]byte
	header[0] = protocolVersion
	header[1] = byte(kind)
	binary.BigEndian.PutUint32(header[2:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readFrame(r io.Reader) (frameType, []byte, error) {
	var header [6]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	kind := frameType(header[1])
	length := binary.BigEndian.Uint32(header[2:])
	if header[0] != protocolVersion || !validFrameType(kind) || length > maxFramePayload {
		return 0, nil, ErrProtocol
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return kind, payload, nil
}

func writeJSONFrame(w io.Writer, kind frameType, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return ErrProtocol
	}
	return writeFrame(w, kind, payload)
}

func decodeStrictJSON(payload []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrProtocol
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrProtocol
	}
	return nil
}

func validateCall(call Call) error {
	if call.Command == "" || len(call.Command) > 32768 || !utf8.ValidString(call.Command) || strings.ContainsRune(call.Command, 0) {
		return ErrProtocol
	}
	if call.Deadline.IsZero() {
		return ErrProtocol
	}
	return nil
}
