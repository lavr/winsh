package remote

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSourceRejectsEmptyPath(t *testing.T) {
	if _, _, err := openSource(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestOpenSourceRejectsMissing(t *testing.T) {
	if _, _, err := openSource(filepath.Join(t.TempDir(), "no-such-file")); err == nil {
		t.Fatal("missing path accepted")
	}
}

func TestOpenSourceRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := openSource(dir); err == nil {
		t.Fatal("directory accepted as source")
	}
}

func TestOpenSourceRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		// Some filesystems / operating systems restrict symlink creation
		// in sandboxed test environments. Skip rather than fail when the
		// host does not allow it.
		if errors.Is(err, errors.New("symlink not supported")) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("symlink unsupported: %v", err)
		}
		t.Fatal(err)
	}
	if _, _, err := openSource(link); err == nil {
		t.Fatal("symlink accepted as source")
	}
}

func TestOpenSourceReadsRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src.bin")
	payload := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	f, info, err := openSource(path)
	if err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
	defer f.Close()
	if !info.Mode().IsRegular() {
		t.Errorf("mode not regular: %s", info.Mode())
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestCreateStageRejectsEmptyDest(t *testing.T) {
	if _, err := createStage(""); err == nil {
		t.Fatal("empty destination accepted")
	}
}

func TestCreateStageRejectsRelativeParent(t *testing.T) {
	if _, err := createStage("relative/path"); err == nil {
		t.Fatal("relative destination accepted")
	}
}

func TestCreateStageRejectsMissingParent(t *testing.T) {
	if _, err := createStage(filepath.Join(t.TempDir(), "no-such-dir", "dest.bin")); err == nil {
		t.Fatal("missing parent accepted")
	}
}

func TestCreateStageRejectsFileParent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := createStage(filepath.Join(file, "dest.bin")); err == nil {
		t.Fatal("file parent accepted")
	}
}

func TestCreateStageExclusive(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")
	f, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	// Stage must be inside the destination's parent.
	if filepath.Dir(f.Name()) != dir {
		t.Errorf("stage outside dest parent: %s", f.Name())
	}
	// Stage must be a fresh file (no preexisting content).
	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Errorf("stage not empty: %d bytes", info.Size())
	}
}

func TestCreateStageUniqueAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")
	a, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(a.Name())
	defer a.Close()
	b, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b.Name())
	defer b.Close()
	if a.Name() == b.Name() {
		t.Fatalf("two createStage calls produced the same name: %s", a.Name())
	}
}

func TestHashStageEmpty(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")
	f, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	n, sum, err := hashStage(f)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("n=%d, want 0", n)
	}
	// SHA-256 of an empty input is well-known.
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if sum != want {
		t.Errorf("hash=%s, want %s", sum, want)
	}
}

func TestHashStageBinary(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")
	f, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	payload := bytes.Repeat([]byte{0xC3, 0x28, 0x00, 0xFF}, 1024)
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	n, sum, err := hashStage(f)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(payload)) {
		t.Errorf("n=%d, want %d", n, len(payload))
	}
	want := sha256.Sum256(payload)
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("hash mismatch")
	}
}

func TestHashStageAfterOverwrite(t *testing.T) {
	// The hash must reflect the bytes on disk, not whatever caller
	// might have in a write buffer. Write a different payload after
	// the initial write and confirm hashStage sees the second one.
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.bin")
	f, err := createStage(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	first := []byte("hello world")
	if _, err := f.Write(first); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	// Overwrite the file with different content via a separate open.
	if err := os.WriteFile(f.Name(), []byte("goodbye"), 0600); err != nil {
		t.Fatal(err)
	}
	n, sum, err := hashStage(f)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len("goodbye")) {
		t.Errorf("n=%d, want %d", n, len("goodbye"))
	}
	want := sha256.Sum256([]byte("goodbye"))
	if sum != hex.EncodeToString(want[:]) {
		t.Errorf("hash did not reflect on-disk content")
	}
}

func TestStagePathAtInsideDirectory(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 100; i++ {
		p, err := stagePathAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(p) != dir {
			t.Errorf("stage path outside directory: %s", p)
		}
		// 8 random bytes -> 16 hex chars plus the prefix -> predictable length.
		base := filepath.Base(p)
		if !strings.HasPrefix(base, ".winsh-stage-") {
			t.Errorf("missing stage prefix: %s", base)
		}
		if len(base) != len(".winsh-stage-")+16 {
			t.Errorf("unexpected basename length: %s", base)
		}
	}
}

func TestRemoteStageParentRejectsRelative(t *testing.T) {
	if _, err := remoteStageParent("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestRemoteStageParentAcceptsDriveRooted(t *testing.T) {
	// The function is purely string-based and Windows-aware: it must
	// accept both backslash and forward-slash drive-rooted paths.
	cases := []string{`C:\Temp\dest.bin`, `C:/Temp/dest.bin`, `D:\a b\dest.bin`}
	for _, p := range cases {
		if _, err := remoteStageParent(p); err != nil {
			t.Errorf("%s rejected: %v", p, err)
		}
	}
}
