package control

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestProtocolSplitFrame(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() {
		frame := append([]byte{protocolVersion, byte(frameStdout), 0, 0, 0, 5}, []byte("hello")...)
		for _, b := range frame {
			if _, err := left.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	kind, payload, err := readFrame(right)
	if err != nil || kind != frameStdout || string(payload) != "hello" {
		t.Fatalf("split frame = %v, %q, %v", kind, payload, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProtocolRejectsInvalidHeader(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header []byte
	}{
		{"oversized", []byte{protocolVersion, byte(frameStdout), 0, 1, 0, 1}},
		{"version", []byte{protocolVersion + 1, byte(frameStdout), 0, 0, 0, 0}},
		{"type", []byte{protocolVersion, 255, 0, 0, 0, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			go func() { _, _ = left.Write(tt.header) }()
			if _, _, err := readFrame(right); !errors.Is(err, ErrProtocol) {
				t.Fatalf("header accepted: %v", err)
			}
		})
	}
}

func TestProtocolRejectsInvalidCall(t *testing.T) {
	call := Call{Identity: Identity{Endpoint: "http://server.example.com:5985/wsman", User: "alice"}, Command: string([]byte{0xff})}
	if err := validateCall(call); !errors.Is(err, ErrProtocol) {
		t.Fatalf("invalid UTF-8 command accepted: %v", err)
	}
	if _, ok := reflect.TypeOf(Call{}).FieldByName("Password"); ok {
		t.Fatal("local protocol grew a password field")
	}
	if _, ok := reflect.TypeOf(Identity{}).FieldByName("Password"); ok {
		t.Fatal("master identity grew a password field")
	}
	var decoded Call
	if err := decodeStrictJSON([]byte(`{"Command":"hostname","Password":"synthetic-password"}`), &decoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("socket request accepted a password field: %v", err)
	}
	call.Command = strings.Repeat("x", 32769)
	if err := validateCall(call); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized command accepted: %v", err)
	}
}

func TestProtocolStreamingFrames(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	const total = 1024 * 1024
	done := make(chan error, 1)
	go func() {
		chunk := bytes.Repeat([]byte("x"), 32*1024)
		for sent := 0; sent < total; sent += len(chunk) {
			if err := writeFrame(left, frameStdout, chunk); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	var count int
	for count < total {
		kind, payload, err := readFrame(right)
		if err != nil || kind != frameStdout {
			t.Fatalf("frame %d: %v, %v", count, kind, err)
		}
		count += len(payload)
	}
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
