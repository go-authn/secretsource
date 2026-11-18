//go:build darwin

package secretsource

import (
	"os"
	"strings"
	"testing"
)

// The per-user temporary directory from confstr is a real directory, with no
// trailing slash (KeePassXC chops it too), and is what the socket path uses.
func TestConfstrTempDir(t *testing.T) {
	d := confstrTempDir()
	if d == "" || strings.HasSuffix(d, "/") {
		t.Fatalf("%q", d)
	}
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		t.Fatalf("%q: %v", d, err)
	}
	c, err := socketCandidates()
	if err != nil || len(c) != 1 || !strings.HasPrefix(c[0], userTempDir()+"/") {
		t.Fatalf("%v %v", c, err)
	}
}
