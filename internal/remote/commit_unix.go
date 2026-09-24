//go:build linux || darwin

package remote

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openSourceOS refuses final-component symlinks and opens nonblocking so a
// concurrent replacement with a FIFO cannot stall before the fstat check.
func openSourceOS(path string) (*os.File, os.FileInfo, error) {
	if info, err := os.Lstat(path); err != nil {
		return nil, nil, err
	} else if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("source %q is not a regular file", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// commitStage performs the final atomic install of stage onto
// destination. With force=false it uses os.Link to create a second
// hardlink at destination; EEXIST leaves the existing destination
// untouched and is reported back. With force=true it uses os.Rename,
// which atomically replaces destination on the same filesystem. Cross-filesystem
// rename fails; no copy-and-delete fallback is attempted.
func commitStage(stage, destination string, force bool) error {
	if stage == "" || destination == "" {
		return errors.New("stage and destination must not be empty")
	}
	if stage == destination {
		return errors.New("stage equals destination")
	}
	if force {
		if err := os.Rename(stage, destination); err != nil {
			return fmt.Errorf("rename (force): %w", err)
		}
		return nil
	}
	if err := os.Link(stage, destination); err != nil {
		return fmt.Errorf("link (no-replace): %w", err)
	}
	return nil
}
