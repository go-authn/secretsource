//go:build unix

package secretsource

import (
	"net"
	"os"
	"path/filepath"
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
