package remote

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// emptySHA256 is the well-known SHA-256 of an empty input, used as the
// expected hash in several record tests.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestReadRecordRejectsDuplicateID(t *testing.T) {
	body := `{"version":1,"id":"first","id":"expected","bytes":0,"sha256":"` + emptySHA256 + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestReadRecordAcceptsValidRecord(t *testing.T) {
	body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `"}`
	rec, err := readRecord(strings.NewReader(body), "expected")
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if rec.Version != 1 || rec.ID != "expected" || rec.Bytes != 0 || rec.SHA256 != emptySHA256 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestReadRecordRejectsUnknownKey(t *testing.T) {
	body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `","extra":"x"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestReadRecordRejectsIDMismatch(t *testing.T) {
	body := `{"version":1,"id":"other","bytes":0,"sha256":"` + emptySHA256 + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("id mismatch accepted")
	}
}

func TestReadRecordRejectsBadVersion(t *testing.T) {
	body := `{"version":2,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("future version accepted")
	}
}

func TestReadRecordRejectsBadHash(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{"too short", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"},
		{"too long", emptySHA256 + "00"},
		{"uppercase hex", strings.ToUpper(emptySHA256)},
		{"non-hex", "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + c.hash + `"}`
			if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
				t.Fatal("invalid hash accepted")
			}
		})
	}
}

func TestReadRecordRejectsNegativeBytes(t *testing.T) {
	body := `{"version":1,"id":"expected","bytes":-1,"sha256":"` + emptySHA256 + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("negative bytes accepted")
	}
}

func TestReadRecordRejectsOversize(t *testing.T) {
	// Construct a JSON object strictly larger than transferRecordMaxSize bytes.
	pad := strings.Repeat("x", transferRecordMaxSize)
	body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `","junk":"` + pad + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("oversize record accepted")
	}
}

func TestReadRecordRejectsNonObject(t *testing.T) {
	if _, err := readRecord(strings.NewReader(`[]`), "expected"); err == nil {
		t.Fatal("array accepted as record")
	}
	if _, err := readRecord(strings.NewReader(`"hello"`), "expected"); err == nil {
		t.Fatal("string accepted as record")
	}
}

func TestCopyBase64Lines(t *testing.T) {
	var got bytes.Buffer
	n, err := copyBase64Lines(&got, strings.NewReader("AAEC\r\n/w==\r\n"), 16)
	if err != nil || n != 4 || !bytes.Equal(got.Bytes(), []byte{0, 1, 2, 255}) {
		t.Fatalf("n=%d err=%v got=%v", n, err, got.Bytes())
	}
}

func TestCopyBase64LinesEmpty(t *testing.T) {
	var got bytes.Buffer
	n, err := copyBase64Lines(&got, strings.NewReader(""), 16)
	if err != nil || n != 0 || got.Len() != 0 {
		t.Fatalf("n=%d err=%v len=%d", n, err, got.Len())
	}
}

func TestCopyBase64LinesEmptyDataLine(t *testing.T) {
	// Empty lines between data lines decode to zero bytes and must not error.
	var got bytes.Buffer
	n, err := copyBase64Lines(&got, strings.NewReader("\r\nAAEC\r\n\r\n/w==\r\n"), 16)
	if err != nil || n != 4 || !bytes.Equal(got.Bytes(), []byte{0, 1, 2, 255}) {
		t.Fatalf("n=%d err=%v got=%v", n, err, got.Bytes())
	}
}

func TestCopyBase64LinesSplitAcrossReads(t *testing.T) {
	// A single line straddles two Read calls. The function must reassemble
	// it without dropping characters or producing spurious empty tokens.
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("AAEC"))
		_, _ = pw.Write([]byte("/w==\r\n"))
		_ = pw.Close()
	}()
	var got bytes.Buffer
	n, err := copyBase64Lines(&got, pr, 16)
	if err != nil || n != 4 || !bytes.Equal(got.Bytes(), []byte{0, 1, 2, 255}) {
		t.Fatalf("n=%d err=%v got=%v", n, err, got.Bytes())
	}
}

func TestCopyBase64LinesCoalescedMultipleLinesInOneRead(t *testing.T) {
	// Several complete lines arrive in a single Read.
	var got bytes.Buffer
	n, err := copyBase64Lines(&got, strings.NewReader("AAEC\r\n/w==\r\nAQID\r\n/w==\r\n"), 16)
	if err != nil || n != 8 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !bytes.Equal(got.Bytes(), []byte{0, 1, 2, 255, 1, 2, 3, 255}) {
		t.Fatalf("got=%v", got.Bytes())
	}
}

func TestCopyBase64LinesMalformedBase64(t *testing.T) {
	if _, err := copyBase64Lines(&bytes.Buffer{}, strings.NewReader("@@@@\r\n"), 16); err == nil {
		t.Fatal("malformed base64 accepted")
	}
}

func TestCopyBase64LinesOverlongWithoutCRLF(t *testing.T) {
	// 17-byte line + no newline -> rejected.
	if _, err := copyBase64Lines(&bytes.Buffer{}, strings.NewReader(strings.Repeat("A", 17)), 16); err == nil {
		t.Fatal("overlong line accepted")
	}
}

func TestCopyBase64LinesMissingTerminalCRLF(t *testing.T) {
	// Last line has no CRLF at EOF -> rejected.
	if _, err := copyBase64Lines(&bytes.Buffer{}, strings.NewReader("AAEC\r\n/w=="), 16); err == nil {
		t.Fatal("missing terminal CRLF accepted")
	}
}

func TestCopyBase64LinesStrayCR(t *testing.T) {
	if _, err := copyBase64Lines(&bytes.Buffer{}, strings.NewReader("AAEC\r/w==\r\n"), 16); err == nil {
		t.Fatal("stray \\r accepted")
	}
}

func TestCopyBase64LinesWriterError(t *testing.T) {
	w := &errWriter{}
	if _, err := copyBase64Lines(w, strings.NewReader("AAEC\r\n"), 16); err == nil {
		t.Fatal("writer error swallowed")
	}
}

func TestCopyBase64LinesShortWrites(t *testing.T) {
	w := &shortWriter{limit: 1}
	n, err := copyBase64Lines(w, strings.NewReader("AAEC\r\n"), 16)
	if err != nil {
		t.Fatalf("short write errored: %v", err)
	}
	if n != 3 {
		t.Fatalf("n=%d want 3", n)
	}
}

func TestReadRecordRejectsMissingRequiredKey(t *testing.T) {
	// Missing "bytes".
	body := `{"version":1,"id":"expected","sha256":"` + emptySHA256 + `"}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("accepted record with missing bytes key")
	}
}

func TestReadRecordRejectsTrailingData(t *testing.T) {
	// Valid record followed by a second JSON value: must be rejected.
	body := `{"version":1,"id":"expected","bytes":0,"sha256":"` + emptySHA256 + `"} {"junk":true}`
	if _, err := readRecord(strings.NewReader(body), "expected"); err == nil {
		t.Fatal("accepted trailing data after JSON object")
	}
}

func TestChunkSizeFindsLargestFittingChunk(t *testing.T) {
	// Fake builder: 200 bytes overhead + ceil(n/3)*4 (base64) + 2 (CRLF).
	builder := func(b []byte) (string, error) {
		if len(b) == 0 {
			return strings.Repeat("x", 200), nil
		}
		encoded := ((len(b) + 2) / 3) * 4
		return strings.Repeat("x", 200+encoded+2), nil
	}
	got, err := chunkSize(1000, builder)
	if err != nil {
		t.Fatal(err)
	}
	// Boundary: largest n with 200 + ceil(n/3)*4 + 2 ≤ 1000
	// ceil(n/3)*4 ≤ 798 → ceil(n/3) ≤ 199 → n/3 ≤ 199 → n ≤ 597
	if got != 597 {
		t.Fatalf("chunk size = %d, want 597", got)
	}
	if s, _ := builder(make([]byte, got)); len(s) > 1000 {
		t.Fatalf("chunk %d produces %d bytes, exceeds envelope", got, len(s))
	}
	if s, _ := builder(make([]byte, got+1)); len(s) <= 1000 {
		t.Fatalf("chunk %d+1 produces %d bytes, should exceed envelope", got, len(s))
	}
}

func TestChunkSizeRejectsZeroEnvelope(t *testing.T) {
	if _, err := chunkSize(0, func([]byte) (string, error) { return "", nil }); err == nil {
		t.Fatal("zero envelope accepted")
	}
}

func TestChunkSizeRejectsNilBuilder(t *testing.T) {
	if _, err := chunkSize(100, nil); err == nil {
		t.Fatal("nil builder accepted")
	}
}

func TestChunkSizePropagatesBuilderError(t *testing.T) {
	want := errors.New("nope")
	if _, err := chunkSize(100, func([]byte) (string, error) { return "", want }); !errors.Is(err, want) {
		t.Fatalf("err=%v want %v", err, want)
	}
}

func TestChunkSizeRejectsUnusableEnvelope(t *testing.T) {
	// Builder whose 1-byte encoding already exceeds the envelope. The
	// binary search would otherwise return 1, which is a value the
	// caller cannot actually transmit.
	if _, err := chunkSize(10, func(b []byte) (string, error) {
		return strings.Repeat("x", 50+len(b)), nil
	}); err == nil {
		t.Fatal("chunkSize accepted an envelope too small for any chunk")
	}
}

func TestValidateRemotePathAcceptsValidPaths(t *testing.T) {
	for _, p := range []string{
		`C:\Temp`,
		`C:\`,
		`C:/Temp/file.bin`,
		`C:\Program Files\App\file.bin`,
		`C:\data\O'Brien [1] Привет 😀.bin`,
		`z:\lower-drive\file`,
		`D:\path with spaces and unicode\файл.txt`,
	} {
		if err := validateRemotePath(p); err != nil {
			t.Errorf("valid path %q rejected: %v", p, err)
		}
	}
}

func TestValidateRemotePathRejectsEmptyAndNUL(t *testing.T) {
	if err := validateRemotePath(""); err == nil {
		t.Error("empty accepted")
	}
	if err := validateRemotePath("C:\x00Temp"); err == nil {
		t.Error("NUL accepted")
	}
}

func TestValidateRemotePathRequiresDriveRoot(t *testing.T) {
	for _, p := range []string{
		"\\Temp",
		"Temp",
		".\\Temp",
		"..\\Temp",
		"file.txt",
	} {
		if err := validateRemotePath(p); err == nil {
			t.Errorf("non-drive-rooted %q accepted", p)
		}
	}
}

func TestValidateRemotePathRejectsUNCAndDevice(t *testing.T) {
	for _, p := range []string{
		`\\server\share`,
		`\\.\COM1`,
		`\\?\C:\Temp`,
	} {
		if err := validateRemotePath(p); err == nil {
			t.Errorf("UNC/device %q accepted", p)
		}
	}
}

func TestValidateRemotePathRejectsAlternateDataStream(t *testing.T) {
	if err := validateRemotePath(`C:\file.txt:hidden`); err == nil {
		t.Error("ADS accepted")
	}
}

func TestValidateRemotePathRejectsWildcards(t *testing.T) {
	for _, p := range []string{
		`C:\file*.txt`,
		`C:\file?.txt`,
	} {
		if err := validateRemotePath(p); err == nil {
			t.Errorf("wildcard %q accepted", p)
		}
	}
}

func TestValidateRemotePathRejectsReservedDeviceNames(t *testing.T) {
	for _, p := range []string{
		`C:\CON`,
		`C:\Temp\PRN.txt`,
		`C:\COM1`,
		`C:\lpt9`,
	} {
		if err := validateRemotePath(p); err == nil {
			t.Errorf("reserved name %q accepted", p)
		}
	}
}

func TestValidateRemotePathRejectsAmbiguousTrailing(t *testing.T) {
	for _, p := range []string{
		`C:\Temp\file. `,
		`C:\Temp\file.. `,
		`C:\Temp\file .txt. `,
	} {
		if err := validateRemotePath(p); err == nil {
			t.Errorf("ambiguous trailing %q accepted", p)
		}
	}
}

// errWriter fails every Write with errWriterErr.
type errWriter struct{}

var errWriterErr = errors.New("write failed")

func (errWriter) Write(p []byte) (int, error) { return 0, errWriterErr }

// shortWriter writes at most `limit` bytes per Write.
type shortWriter struct{ limit int }

func (s *shortWriter) Write(p []byte) (int, error) {
	if len(p) <= s.limit {
		return len(p), nil
	}
	return s.limit, io.ErrShortWrite
}
