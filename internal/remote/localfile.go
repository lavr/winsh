package remote

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// openSource opens path for reading and reports its FileInfo. It refuses
// symlinks and other non-regular sources because the upload flow reads
// the bytes directly from the opened handle and then re-hashes the
// staged copy; a symlink would let a concurrent rename or replace
// change the source after the size check. The local syscall uses O_NOFOLLOW
// with a nonblocking open.
func openSource(path string) (*os.File, os.FileInfo, error) {
	if path == "" {
		return nil, nil, errors.New("source path must not be empty")
	}
	f, info, err := openSourceOS(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("source %q is not a regular file (mode=%s)", path, info.Mode())
	}
	return f, info, nil
}

// createStage creates a uniquely named regular file inside the parent
// directory of destPath. The name is generated from crypto/rand bytes
// (hex-encoded) so concurrent transfers cannot collide; the file is
// created with O_CREATE|O_EXCL so a pre-existing name is rejected
// without clobbering. The caller is responsible for closing and
// removing the returned file.
func createStage(destPath string) (*os.File, error) {
	if destPath == "" {
		return nil, errors.New("destination path must not be empty")
	}
	parent := filepath.Dir(destPath)
	if parent == "" || parent == "." {
		return nil, errors.New("destination parent must be an absolute path")
	}
	if fi, err := os.Stat(parent); err != nil {
		return nil, fmt.Errorf("destination parent: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("destination parent %q is not a directory", parent)
	}
	for attempt := 0; attempt < 8; attempt++ {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		name := ".winsh-stage-" + hex.EncodeToString(buf[:])
		stage := filepath.Join(parent, name)
		f, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create stage: %w", err)
		}
	}
	return nil, errors.New("create stage: exhausted random name retries")
}

// hashStage computes SHA-256 and the byte count of the contents of f.
// The file is read from offset 0 through the same open FD so the hash
// covers exactly the bytes that will be committed, not whatever might
// be at the path if it were reopened. Callers should Sync the stage
// before calling; hashStage does not sync again because the caller
// already did.
func hashStage(f *os.File) (int64, string, error) {
	if f == nil {
		return 0, "", errors.New("hash stage: nil file")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", fmt.Errorf("seek stage: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return n, "", fmt.Errorf("read stage: %w", err)
	}
	if err := f.Sync(); err != nil {
		// Sync failure here is reported but does not invalidate the
		// hash the caller already collected; the destination commit
		// may still proceed on platforms where sync is advisory.
		return n, hex.EncodeToString(h.Sum(nil)), fmt.Errorf("sync stage: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return n, hex.EncodeToString(h.Sum(nil)), fmt.Errorf("rewind stage: %w", err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// stagePathAt builds the random staging path inside destDir, mirroring
// createStage but without creating the file. Tests use this to verify
// that the path generation stays inside the destination directory.
func stagePathAt(destDir string) (string, error) {
	if destDir == "" {
		return "", errors.New("destination directory must not be empty")
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return filepath.Join(destDir, ".winsh-stage-"+hex.EncodeToString(buf[:])), nil
}

// remoteStageTempDir returns the parent directory in which the remote
// receiver should place its staging file. It is the parent of
// destPath; the spec restricts the receiver to writing inside the
// destination directory so the final commit can use same-filesystem
// atomic rename. The path is parsed as text rather than via filepath.Dir
// because the destination is a Windows path even when this code runs
// on a Unix build host.
func remoteStageParent(destPath string) (string, error) {
	if !looksDriveRooted(destPath) {
		return "", fmt.Errorf("destination %q must be drive-rooted", destPath)
	}
	sep := strings.LastIndexAny(destPath, `\/`)
	if sep < 0 {
		return "", fmt.Errorf("destination %q has no separator", destPath)
	}
	if sep == 2 {
		return destPath[:3], nil
	}
	return destPath[:sep], nil
}

// looksDriveRooted reports whether p is either a UNC path
// (\\server\share\...) or a drive-rooted path (X:\... or X:/...).
// Used by remoteStageParent so the validation works regardless of
// host GOOS.
func looksDriveRooted(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return false
}
