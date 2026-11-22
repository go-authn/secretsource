//go:build unix

package secretsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openFile(t *testing.T, p string) error {
	t.Helper()
	s, err := Open(context.Background(), "file:"+p)
	if err == nil {
		s.Close()
	}
	return err
}

func wantSymlinkRefusal(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("a symlink was followed")
	}
	for _, w := range []string{"symbolic link", "point at the file it names"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q lacks %q", err, w)
		}
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		t.Error("the error echoes the contents")
	}
}

func TestFileSchemeRefusesASymlinkToAGoodFile(t *testing.T) {
	target := writeSecret(t, "hunter2-secret", 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	wantSymlinkRefusal(t, openFile(t, link), "hunter2")
	if err := openFile(t, target); err != nil {
		t.Errorf("the target itself: %v", err)
	}
}

func TestFileSchemeRefusesADanglingSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "dangling")
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), link); err != nil {
		t.Fatal(err)
	}
	err := openFile(t, link)
	wantSymlinkRefusal(t, err, "")
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("a dangling link reads as a missing file: %v", err)
	}
}

func TestFileSchemeStillFollowsDirectoriesInThePath(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "pin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := openFile(t, filepath.Join(dir, "dirlink", "pin")); err != nil {
		t.Errorf("a symlinked directory component: %v", err)
	}
}

// A loop among the directories is ELOOP too, but no last-component symlink: the
// original error comes back, not a message that blames a link that is not there.
func TestFileSchemeDirectoryLoopKeepsItsOwnError(t *testing.T) {
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	err := openFile(t, filepath.Join(loop, "pin"))
	if err == nil || strings.Contains(err.Error(), "point at the file it names") {
		t.Errorf("got %v", err)
	}
}

func TestFileSchemeRefusesAFileOwnedByAnotherUser(t *testing.T) {
	p := writeSecret(t, "owned-by-someone-else", 0o600)
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return os.Geteuid() + 12345 }
	err := openFile(t, p)
	if err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "someone-else") {
		t.Error("the error echoes the contents")
	}
	// Root is not let in either: only the caller's own uid is.
	if os.Geteuid() != 0 {
		geteuid = func() int { return 0 }
		if err := openFile(t, p); err == nil {
			t.Error("a file owned by a non-root user was accepted as root")
		}
	}
}

func TestCheckFileOwnerWithoutAStatT(t *testing.T) {
	st, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFileOwner(noSys{st}, "p"); err == nil || !strings.Contains(err.Error(), "cannot tell who owns") {
		t.Errorf("got %v", err)
	}
}

type noSys struct{ os.FileInfo }

func (noSys) Sys() any { return nil }
