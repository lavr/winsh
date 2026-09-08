package remote

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type testSession struct{ fail bool }

func (s testSession) Wrap(b []byte) ([]byte, []byte, error) {
	if s.fail {
		return nil, nil, errors.New("wrap failed")
	}
	return b, bytes.Repeat([]byte{42}, 16), nil
}
func (s testSession) Unwrap(b, sig []byte) ([]byte, error) {
	if s.fail || !bytes.Equal(sig, bytes.Repeat([]byte{42}, 16)) {
		return nil, errors.New("bad signature")
	}
	return b, nil
}

func TestSealedFrame(t *testing.T) {
	input := []byte("<soap>Привет</soap>")
	body, ct, err := sealMessage(testSession{}, input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unsealMessage(testSession{}, body, ct)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("roundtrip: %q %v", got, err)
	}
	if !strings.Contains(string(body), "Length=25") {
		t.Errorf("incorrect byte length: %q", body)
	}
	for _, tt := range []struct {
		name string
		body []byte
		ct   string
	}{
		{"short", []byte("x"), ct},
		{"plaintext", input, "application/soap+xml"},
		{"invalid length", bytes.Replace(body, []byte("Length=25"), []byte("Length=99"), 1), ct},
		{"truncated", body[:len(body)-6], ct},
		{"missing header", body, "multipart/encrypted"},
		{"huge signature", bytes.Replace(body, []byte{16, 0, 0, 0}, []byte{255, 255, 255, 255}, 1), ct},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := unsealMessage(testSession{}, tt.body, tt.ct); err == nil {
				t.Fatal("accepted malformed message")
			}
		})
	}
	if _, _, err := sealMessage(testSession{fail: true}, input); err == nil {
		t.Fatal("ignored wrap error")
	}
	if _, err := unsealMessage(testSession{fail: true}, body, ct); err == nil {
		t.Fatal("ignored signature failure")
	}
}

func FuzzUnseal(f *testing.F) {
	f.Add([]byte("bad"), "multipart/encrypted")
	f.Fuzz(func(t *testing.T, b []byte, ct string) { _, _ = unsealMessage(testSession{}, b, ct) })
}
