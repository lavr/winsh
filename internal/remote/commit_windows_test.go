//go:build windows

package remote

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitPreservesConcurrentDestination(t *testing.T) {
	dir := t.TempDir()
	stage, dest := filepath.Join(dir, "stage"), filepath.Join(dir, "dest")
	if err := os.WriteFile(stage, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("other writer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := commitStage(stage, dest, false); err == nil {
		t.Fatal("replaced destination")
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "other writer" {
		t.Fatalf("destination changed: got=%q err=%v", got, err)
	}
}

func TestCommitRefusesOnExistingNoForce(t *testing.T) {
	dir := t.TempDir()
	stage, dest := filepath.Join(dir, "stage"), filepath.Join(dir, "dest")
	if err := os.WriteFile(stage, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := commitStage(stage, dest, false); err == nil {
		t.Fatal("refused expected")
	}
	if _, err := os.Stat(stage); err != nil {
		t.Errorf("stage removed on refused commit: %v", err)
	}
}

func TestCommitReplacesOnForce(t *testing.T) {
	dir := t.TempDir()
	stage, dest := filepath.Join(dir, "stage"), filepath.Join(dir, "dest")
	if err := os.WriteFile(stage, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := commitStage(stage, dest, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("dest not replaced: %q", got)
	}
}

func TestCommitInstallsFromAbsentDest(t *testing.T) {
	dir := t.TempDir()
	stage, dest := filepath.Join(dir, "stage"), filepath.Join(dir, "dest")
	if err := os.WriteFile(stage, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := commitStage(stage, dest, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "hello" {
		t.Fatalf("install failed: got=%q err=%v", got, err)
	}
}

func TestCommitRejectsSamePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := commitStage(p, p, false); err == nil {
		t.Fatal("stage==destination accepted")
	}
}

func TestCommitRejectsEmptyArgs(t *testing.T) {
	if err := commitStage("", filepath.Join(t.TempDir(), "x"), false); err == nil {
		t.Fatal("empty stage accepted")
	}
	if err := commitStage(filepath.Join(t.TempDir(), "x"), "", false); err == nil {
		t.Fatal("empty destination accepted")
	}
}

func TestCommitMissingStage(t *testing.T) {
	dir := t.TempDir()
	err := commitStage(filepath.Join(dir, "no-such-stage"), filepath.Join(dir, "dest"), false)
	if err == nil {
		t.Fatal("missing stage accepted")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no-such-stage") {
		t.Errorf("expected not-exist error, got: %v", err)
	}
}
