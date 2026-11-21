//go:build unix

package secretsource

// Security audit 2026-11-21 (secaudit5). These tests assert the SAFE behaviour
// and are expected to FAIL on the audited commit.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// "Every call is bounded ... the call ends with the context": file: opens the
// path before it knows what it is, and opening a FIFO nobody writes to blocks
// outside any context.
func TestSecaudit5FileRefOnAFIFOIgnoresTheContext(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pin")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, err := Open(ctx, "file:"+p)
		s.Close()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read as a secret")
		}
	case <-time.After(10 * time.Second):
		// Let the goroutine go: give the FIFO a writer.
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("Open(file:FIFO) was still blocked 10 s after a 300 ms context ended")
	}
}

// checkSocket stats THROUGH a symlink and looks at the owner of the socket
// only, so a path in a directory somebody else controls passes while it points
// at any socket of ours, and can be re-pointed before the dial.
func TestSecaudit5CheckSocketAcceptsASymlinkInAWorldWritableDirectory(t *testing.T) {
	base, err := os.MkdirTemp("", "s5")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	mine := filepath.Join(base, "m")
	theirs := filepath.Join(base, "t") // stands for /tmp/runtime-$USER made by somebody else
	for _, d := range []string{mine, theirs} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(theirs, 0o777); err != nil {
		t.Fatal(err)
	}
	real, err := net.Listen("unix", filepath.Join(mine, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	other, err := net.Listen("unix", filepath.Join(mine, "o"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	link := filepath.Join(theirs, sockName)
	if err := os.Symlink(filepath.Join(mine, "s"), link); err != nil {
		t.Fatal(err)
	}
	checked := checkSocket(link)
	// Between the check and the dial the link is re-pointed.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(mine, "o"), link); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	got, err := other.Accept()
	if err != nil {
		t.Fatal(err)
	}
	got.Close()
	if checked == nil {
		t.Fatal("checkSocket accepted a symlink in a mode-0777 directory; re-pointed after the check, the dial reached another listener")
	}
}
