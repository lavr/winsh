//go:build windows

package remote

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openSourceOS opens path with FILE_FLAG_OPEN_REPARSE_POINT so that a
// reparse point (symlink, junction) is opened as itself rather than its
// target. A subsequent Stat classifies the file: regular files pass,
// anything else fails through the wrapper's Mode().IsRegular check.
func openSourceOS(path string) (*os.File, os.FileInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, fmt.Errorf("utf16 path: %w", err)
	}
	const (
		genericRead         = 0x80000000
		fileShareRead       = 0x00000001
		openExisting        = 3
		fileFlagOpenReparse = 0x00200000
	)
	handle, err := windows.CreateFile(
		pathPtr,
		genericRead,
		fileShareRead,
		nil,
		openExisting,
		fileFlagOpenReparse,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(handle), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// commitStage performs the final atomic install of stage onto
// destination using MoveFileExW. With force=false it passes flag 0 so
// the call refuses with ERROR_ALREADY_EXISTS when destination exists,
// preserving the previous contents. With force=true it sets
// MOVEFILE_REPLACE_EXISTING so destination is replaced atomically.
// MOVEFILE_COPY_ALLOWED is never set, so a cross-volume move fails
// rather than degrading to a non-atomic copy+delete.
func commitStage(stage, destination string, force bool) error {
	if stage == "" || destination == "" {
		return errors.New("stage and destination must not be empty")
	}
	if stage == destination {
		return errors.New("stage equals destination")
	}
	fromPtr, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		return fmt.Errorf("utf16 stage: %w", err)
	}
	toPtr, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return fmt.Errorf("utf16 destination: %w", err)
	}
	var flags uint32
	if force {
		flags = windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(fromPtr, toPtr, flags); err != nil {
		return fmt.Errorf("movefileex: %w", err)
	}
	return nil
}
