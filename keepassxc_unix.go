//go:build unix

package secretsource

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// getuid is replaced by tests.
var getuid = os.Getuid

// checkSocket refuses a path that is not a socket owned by this user, reached
// without a symlink, in a directory that only this user can write: nothing is
// sent to a socket someone else could have put there or re-pointed (on Linux
// the fallback directory is under /tmp). It is a first filter; the connection
// itself is then checked with checkPeer, because a path can change between the
// check and the dial.
func checkSocket(path string) error {
	dir := filepath.Dir(path)
	dst, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !dst.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if sys, ok := dst.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != getuid() {
		return fmt.Errorf("%s belongs to another user", dir)
	}
	if dst.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", dir)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", path)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != getuid() {
		return fmt.Errorf("%s belongs to another user", path)
	}
	return nil
}

// checkPeer refuses a connected Unix socket whose other end is a process of
// another user, as the kernel reports it (SO_PEERCRED, LOCAL_PEERCRED).
func checkPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var uid int
	var perr error
	if err := raw.Control(func(fd uintptr) { uid, perr = peerUID(int(fd)) }); err != nil {
		return err
	}
	if perr != nil {
		return fmt.Errorf("cannot read the peer's credentials: %w", perr)
	}
	if uid != getuid() {
		return fmt.Errorf("the socket's peer belongs to another user")
	}
	return nil
}
