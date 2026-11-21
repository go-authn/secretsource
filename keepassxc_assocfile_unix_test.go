//go:build unix

package secretsource

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDir(t *testing.T) {
	d := shortDir(t)
	if err := checkDir(d); err != nil {
		t.Fatalf("a private directory: %v", err)
	}
	if err := checkDir(filepath.Join(d, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing directory: %v", err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a symlink to a private directory: %v", err)
	}
	for _, mode := range []os.FileMode{0o770, 0o707} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkDir(d); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	old := getuid
	t.Cleanup(func() { getuid = old })
	getuid = func() int { return os.Getuid() + 1 }
	if err := checkDir(d); err == nil || !strings.Contains(err.Error(), "belongs to another user") {
		t.Errorf("another user's directory: %v", err)
	}
}

func TestLstatOfAMissingPathIsNobodys(t *testing.T) {
	st, err := lstat(filepath.Join(shortDir(t), "missing"))
	if !errors.Is(err, fs.ErrNotExist) || st.mine || st.mode != 0 {
		t.Errorf("%+v %v", st, err)
	}
}

func TestCheckPeerRefusesWhatIsNotAUnixConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := checkPeer(a); err == nil || !strings.Contains(err.Error(), "is not a Unix socket connection") {
		t.Errorf("a pipe: %v", err)
	}
}

func assocDir(t *testing.T) (config, dir, file string) {
	t.Helper()
	config = t.TempDir()
	configDirIs(t, config, nil)
	dir = filepath.Join(config, "secretsource")
	file = filepath.Join(dir, "keepassxc-ab.json")
	return config, dir, file
}

// The association key is written to a new file and renamed, so a symlink left at
// the path is replaced, not followed, and a file of loose mode comes out 0600.
func TestFileStoreSaveDoesNotFollowASymlink(t *testing.T) {
	_, dir, file := assocDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, file); err != nil {
		t.Fatal(err)
	}
	var f fileStore
	if err := f.save("ab", assoc{ID: "i", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("the symlink target was written: %q", b)
	}
	st, err := os.Lstat(file)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o600 {
		t.Errorf("%v %v", st, err)
	}
	if a, err := f.load("ab"); err != nil || a.ID != "i" || a.Key != "k" {
		t.Errorf("%+v %v", a, err)
	}
}

func TestFileStoreSaveResetsTheModeOfAnExistingFile(t *testing.T) {
	_, dir, file := assocDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	var f fileStore
	if err := f.save("ab", assoc{ID: "i", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("%v %v", st, err)
	}
	assertNoTemp(t, dir)
}

// The directory is checked before anything is written into it.
func TestFileStoreSaveRefusesAnUnsafeDirectory(t *testing.T) {
	var f fileStore
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, dir string)
		want string
	}{
		{"group-writable", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
		}, "writable by group or others"},
		{"world-writable", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o707); err != nil {
				t.Fatal(err)
			}
		}, "writable by group or others"},
		{"symlink", func(t *testing.T, dir string) {
			real := filepath.Join(filepath.Dir(dir), "real")
			if err := os.Rename(dir, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, dir); err != nil {
				t.Fatal(err)
			}
		}, "symbolic link"},
		{"another user", func(t *testing.T, dir string) {
			old := getuid
			t.Cleanup(func() { getuid = old })
			getuid = func() int { return os.Getuid() + 1 }
		}, "belongs to another user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, dir, file := assocDir(t)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.set(t, dir)
			err := f.save("ab", assoc{ID: "i", Key: "k"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v", err)
			}
			if _, err := os.Lstat(file); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the key was written into an unsafe directory: %v", err)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Errorf("files left in an unsafe directory: %v", entries)
			}
		})
	}
	// The other side: a private directory is written.
	_, dir, file := assocDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.save("ab", assoc{ID: "i", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(file); err != nil {
		t.Error(err)
	}
}
