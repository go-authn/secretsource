//go:build unix

package secretsource

import (
	"os"
	"strings"
	"testing"
)

// checkOwner: the same socket owned by someone else is refused.
func checkOwner(t *testing.T, path string) {
	t.Helper()
	old := getuid
	defer func() { getuid = old }()
	getuid = func() int { return os.Getuid() + 1 }
	if err := checkSocket(path); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("foreign owner: %v", err)
	}
}
