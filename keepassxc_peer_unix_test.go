//go:build unix

package secretsource

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func listenIn(t *testing.T, dir string) (string, net.Listener) {
	t.Helper()
	p := filepath.Join(dir, sockName)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return p, l
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestCheckSocketDirectoryAndSymlink(t *testing.T) {
	d := shortDir(t)
	p, _ := listenIn(t, d)
	if err := checkSocket(p); err != nil {
		t.Fatalf("a socket in a private directory: %v", err)
	}
	// A symlink to the same socket, even in a private directory.
	link := filepath.Join(d, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %v", err)
	}
	// Group-writable and world-writable directories.
	for _, mode := range []os.FileMode{0o770, 0o707} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkSocket(p); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	// A directory of another user.
	old := getuid
	defer func() { getuid = old }()
	getuid = func() int { return os.Getuid() + 1 }
	if err := checkSocket(p); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Errorf("foreign directory: %v", err)
	}
}

func TestCheckSocketRefusesWhatIsNotThere(t *testing.T) {
	d := shortDir(t)
	if err := checkSocket(filepath.Join(d, "missing", sockName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing directory: %v", err)
	}
	if err := checkSocket(filepath.Join(d, sockName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing socket: %v", err)
	}
	f := filepath.Join(d, sockName)
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(f); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("a regular file: %v", err)
	}
}

func TestCheckPeerRefusesWhatItCannotAsk(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := checkPeer(a); err == nil {
		t.Error("a net.Pipe has no peer credentials and was accepted")
	}
	d := shortDir(t)
	p, l := listenIn(t, d)
	defer l.Close()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := checkPeer(c); err == nil || !strings.Contains(err.Error(), "cannot read the peer's credentials") {
		t.Errorf("a closed connection: %v", err)
	}
}

// dialKeePassXC closes and refuses a connection whose peer is not this user.
func TestDialRefusesAForeignPeer(t *testing.T) {
	d := shortDir(t)
	_, l := listenIn(t, d)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	oldOS, oldEnv, oldUID := goos, getenv, getuid
	defer func() { goos, getenv, getuid = oldOS, oldEnv, oldUID }()
	goos = "linux"
	getenv = func(string) string { return d }
	if c, err := dialKeePassXC(context.Background()); err != nil {
		t.Fatalf("own peer: %v", err)
	} else {
		c.Close()
	}
	// Directory and socket pass as ours; only the peer check says no.
	calls := 0
	getuid = func() int {
		calls++
		if calls <= 1 { // the directory check
			return oldUID()
		}
		return oldUID() + 1
	}
	_, err := dialKeePassXC(context.Background())
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "peer belongs to another user") {
		t.Fatalf("foreign peer: %v", err)
	}
}

func TestPeerUIDOfABadDescriptorIsAnError(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		t.Skip("no peer credentials on this system")
	}
	if _, err := peerUID(-1); err == nil {
		t.Fatal("no error for a bad descriptor")
	}
}

func TestCheckPeer(t *testing.T) {
	d := shortDir(t)
	p, l := listenIn(t, d)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := checkPeer(c); err != nil {
		t.Fatalf("own process as peer: %v", err)
	}
	old := getuid
	defer func() { getuid = old }()
	getuid = func() int { return os.Getuid() + 1 }
	if err := checkPeer(c); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Errorf("foreign peer: %v", err)
	}
}
