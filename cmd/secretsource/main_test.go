package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

func run(args ...string) (out, errOut string, err error) {
	c := RootCmd()
	var o, e bytes.Buffer
	c.SetOut(&o)
	c.SetErr(&e)
	c.SetArgs(args)
	err = c.Execute()
	return o.String(), e.String(), err
}

func TestAssociate(t *testing.T) {
	old := associate
	t.Cleanup(func() { associate = old })
	associate = func(context.Context) (secretsource.Association, error) {
		return secretsource.Association{ID: "laptop", Database: "ab12"}, nil
	}
	out, e, err := run("keepassxc", "associate")
	if err != nil || !strings.Contains(out, `"laptop"`) || !strings.Contains(out, "ab12") || !strings.Contains(e, "Approve") {
		t.Fatalf("%q %q %v", out, e, err)
	}
	associate = func(context.Context) (secretsource.Association, error) {
		return secretsource.Association{}, errors.New("boom")
	}
	if _, _, err := run("keepassxc", "associate"); err == nil {
		t.Fatal("no error")
	}
}

func TestCheckNeverPrintsTheSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := run("check", "file:"+p)
	if err != nil || strings.Contains(out, "hunter2") || !strings.Contains(out, "7 bytes") {
		t.Fatalf("%q %v", out, err)
	}
	out, _, err = run("check", "file:"+p+".missing")
	if err == nil || out != "" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestMain_ReportsAndExits(t *testing.T) {
	oldExit, oldArgs := osExit, os.Args
	t.Cleanup(func() { osExit, os.Args = oldExit, oldArgs })
	code := -1
	osExit = func(c int) { code = c }
	os.Args = []string{"secretsource", "check", "nope"}
	main()
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	code = -1
	os.Args = []string{"secretsource", "--help"}
	main()
	if code != -1 {
		t.Fatalf("--help exited %d", code)
	}
}
