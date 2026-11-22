//go:build windows

package secretsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func openFileW(t *testing.T, p string) error {
	t.Helper()
	s, err := Open(context.Background(), "file:"+p)
	if err == nil {
		s.Close()
	}
	return err
}

func TestOpenSecretFileRefusesAReparsePoint(t *testing.T) {
	target := newSecret(t, "hunter2-secret")
	protect(t, target, "(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no privilege to create a symlink: %v", err)
	}
	err := openFileW(t, link)
	if err == nil || !strings.Contains(err.Error(), "reparse point") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("got %v", err)
	}
	if err := openFileW(t, target); err != nil {
		t.Errorf("the target itself: %v", err)
	}
}

func TestOpenSecretFileRefusesADanglingSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "dangling")
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), link); err != nil {
		t.Skipf("no privilege to create a symlink: %v", err)
	}
	if err := openFileW(t, link); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("got %v", err)
	}
}

func TestOpenSecretFileReparseAttributeSeam(t *testing.T) {
	old := fileAttrs
	defer func() { fileAttrs = old }()
	p := newSecret(t, "x")
	fileAttrs = func(windows.Handle) (uint32, error) { return windows.FILE_ATTRIBUTE_REPARSE_POINT, nil }
	if err := openFileW(t, p); err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("reparse attribute: %v", err)
	}
	boom := errors.New("boom")
	fileAttrs = func(windows.Handle) (uint32, error) { return 0, boom }
	if err := openFileW(t, p); !errors.Is(err, boom) {
		t.Errorf("attribute failure: %v", err)
	}
}

func TestOpenSecretFileBadPathAndMissing(t *testing.T) {
	if _, err := openSecretFile("a\x00b"); err == nil {
		t.Error("a NUL in the path was accepted")
	}
	if _, err := openSecretFile(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}
