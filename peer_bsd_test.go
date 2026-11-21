//go:build darwin || freebsd

package secretsource

import (
	"testing"

	"golang.org/x/sys/unix"
)

// A socket that is not connected has no peer: the kernel's refusal reaches the
// caller instead of a zero uid.
func TestPeerUIDOfAnUnconnectedSocketIsAnError(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if uid, err := peerUID(fd); err == nil {
		t.Fatalf("an unconnected socket has a peer uid %d", uid)
	}
}
