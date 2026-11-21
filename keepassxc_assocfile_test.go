package secretsource

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configDirIs(t *testing.T, dir string, err error) {
	t.Helper()
	old := userConfigDir
	userConfigDir = func() (string, error) { return dir, err }
	t.Cleanup(func() { userConfigDir = old })
}

// The association file is reached through a configuration directory that can
// fail to be named, and then every step says so itself, not through what the
// next step would have said of an empty path.
func TestFileStoreErrorsAreEachGuardsOwn(t *testing.T) {
	noHome := errors.New("no home")
	configDirIs(t, "", noHome)
	var f fileStore

	if _, err := f.load("ab"); !errors.Is(err, noHome) || errors.Is(err, ErrNotAssociated) {
		t.Errorf("load without a configuration directory: %v", err)
	}
	if err := f.save("ab", assoc{ID: "i", Key: "k"}); !errors.Is(err, noHome) {
		t.Errorf("save without a configuration directory: %v", err)
	}
	if _, err := f.path("ab"); !errors.Is(err, noHome) {
		t.Errorf("path without a configuration directory: %v", err)
	}

	// The other side: a configuration directory is a path, and a missing file is
	// "not associated", not an error of the directory.
	dir := t.TempDir()
	configDirIs(t, dir, nil)
	if _, err := f.load("ab"); !errors.Is(err, ErrNotAssociated) || errors.Is(err, noHome) {
		t.Errorf("load of a missing file: %v", err)
	}

	// A configuration directory that is a file: the directory cannot be made, and
	// the error is the one of making it.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	configDirIs(t, blocker, nil)
	err := f.save("ab", assoc{ID: "i", Key: "k"})
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "mkdir" {
		t.Errorf("save under a file: %v", err)
	}
}

// dialKeePassXC says why when there is nowhere to dial, and says something else
// when there is somewhere.
func TestDialKeePassXCSaysWhyThereIsNowhereToDial(t *testing.T) {
	oldOS, oldEnv := goos, getenv
	t.Cleanup(func() { goos, getenv = oldOS, oldEnv })

	goos = "windows"
	_, err := dialKeePassXC(context.Background())
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "named pipe") || strings.Contains(err.Error(), "Browser Integration") {
		t.Errorf("windows: %v", err)
	}

	goos = "linux"
	getenv = func(string) string { return t.TempDir() }
	_, err = dialKeePassXC(context.Background())
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "named pipe") || !strings.Contains(err.Error(), "Browser Integration") {
		t.Errorf("linux without a socket: %v", err)
	}
}

func TestWriteAtomicFailures(t *testing.T) {
	dir := t.TempDir()

	// No directory to make the temporary file in.
	if err := writeAtomic(filepath.Join(dir, "missing", "f"), []byte("x")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no directory: %v", err)
	}

	// A temporary file that cannot be written: nothing is renamed, nothing is left.
	old := createTemp
	t.Cleanup(func() { createTemp = old })
	createTemp = func(d, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(d, pattern)
		if err != nil {
			return nil, err
		}
		f.Close()
		return f, nil
	}
	target := filepath.Join(dir, "f")
	if err := writeAtomic(target, []byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("a closed temporary file: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the target exists after a failed write: %v", err)
	}
	createTemp = old
	assertNoTemp(t, dir)

	// A target that cannot be replaced: a directory with something in it.
	if err := os.MkdirAll(filepath.Join(target, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("x")); err == nil {
		t.Error("a directory was replaced")
	}
	assertNoTemp(t, dir)

	// The other side: a free target is written whole.
	free := filepath.Join(dir, "free")
	if err := writeAtomic(free, []byte("whole")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(free); err != nil || string(b) != "whole" {
		t.Errorf("%q %v", b, err)
	}
	assertNoTemp(t, dir)
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".keepassxc-*.tmp"))
	if err != nil || len(m) != 0 {
		t.Errorf("temporary files left: %v %v", m, err)
	}
}

// failsOnce fails its n-th read and no other, so that what follows a failure
// still has entropy: a failure that is not stopped is then seen as a success.
type failsOnce struct{ n, reads int }

func (r *failsOnce) Read(p []byte) (int, error) {
	r.reads++
	if r.reads-1 == r.n {
		return 0, errors.New("entropy glitch")
	}
	return rand.Read(p)
}

// Every random read Associate makes is needed: failing any single one fails it,
// and only a read it never makes lets it through.
func TestAssociateStopsAtEachFailedRead(t *testing.T) {
	old := randReader
	t.Cleanup(func() { randReader = old })
	failed, firstOK := 0, -1
	for n := 0; n < 12; n++ {
		withFake(t, newFake())
		randReader = &failsOnce{n: n}
		_, err := Associate(context.Background())
		switch {
		case err == nil && firstOK < 0:
			firstOK = n
		case err != nil && firstOK >= 0:
			t.Fatalf("read %d was ignored: Associate succeeded at read %d", firstOK, n)
		case err != nil:
			failed++
			if !strings.Contains(err.Error(), "entropy glitch") {
				t.Errorf("n=%d: %v", n, err)
			}
		}
	}
	if failed < 4 || firstOK < failed {
		t.Errorf("failed %d reads, first success at %d", failed, firstOK)
	}
}

func TestIdentityKeyFailure(t *testing.T) {
	old := randReader
	t.Cleanup(func() { randReader = old })
	randReader = &failingReader{}
	if k, err := identityKey(); err == nil || k != [32]byte{} {
		t.Errorf("%x %v", k, err)
	}
	randReader = old
	if k, err := identityKey(); err != nil || k == [32]byte{} {
		t.Errorf("%x %v", k, err)
	}
}
