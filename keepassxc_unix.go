//go:build unix

package secretsource

import (
	"fmt"
	"os"
	"syscall"
)

// getuid is replaced by tests.
var getuid = os.Getuid

// checkSocket refuses a path that is not a socket owned by this user:
// nothing is sent to a socket someone else could have put there (on Linux the
// fallback directory is under /tmp).
func checkSocket(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != getuid() {
		return fmt.Errorf("%s belongs to another user", path)
	}
	return nil
}
