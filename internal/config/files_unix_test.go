//go:build darwin || linux

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestReadFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err == nil {
		t.Fatal("accepted FIFO")
	}
}

func TestUseContextPreservesSymlinkAndRestrictsPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(path, []byte(sample), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	c, err := Load(link)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.UseContext("stage"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("replaced symlink")
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}
