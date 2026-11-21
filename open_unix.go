//go:build unix

package secretsource

import (
	"os"
	"syscall"
)

// openSecretFile opens without blocking: a FIFO nobody writes to would
// otherwise hold open(2) forever, outside any context. The caller checks the
// descriptor is a regular file; O_NONBLOCK changes nothing for one.
func openSecretFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
