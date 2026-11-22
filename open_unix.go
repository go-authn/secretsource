//go:build unix

package secretsource

import (
	"os"
	"syscall"
)

// openSecretFile opens without blocking: a FIFO nobody writes to would
// otherwise hold open(2) forever, outside any context. The caller checks the
// descriptor is a regular file; O_NONBLOCK changes nothing for one.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}

func openSecretFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
