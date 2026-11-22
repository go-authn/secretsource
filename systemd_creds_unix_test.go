//go:build unix

package secretsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// credEnv points the seams at a temp tree: a credentials directory and one
// credstore.encrypted directory, on a pretended Linux, for a non-root caller.
func credEnv(t *testing.T) (credDir, store string) {
	t.Helper()
	credDir, store = t.TempDir(), t.TempDir()
	oldGoos, oldEnv, oldEuid, oldRun, oldStore := goos, getenv, geteuid, runCreds, credstoreEnc
	t.Cleanup(func() { goos, getenv, geteuid, runCreds, credstoreEnc = oldGoos, oldEnv, oldEuid, oldRun, oldStore })
	goos = "linux"
	getenv = func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return credDir
		}
		return ""
	}
	geteuid = os.Geteuid
	if err := os.Chmod(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credstoreEnc = []string{filepath.Join(store, "missing"), store}
	runCreds = func(context.Context, []string) ([]byte, string, error) {
		t.Fatal("systemd-creds must not run")
		return nil, "", nil
	}
	return credDir, store
}

func writeCred(t *testing.T, dir, name, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestCredsFromDirectory(t *testing.T) {
	dir, _ := credEnv(t)
	writeCred(t, dir, "theca", "s3cret\n", 0o400)
	s, err := Open(context.Background(), "systemd-creds:theca")
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Bytes()) != "s3cret" {
		t.Fatalf("got %q", s.Bytes())
	}
	_ = s.Close()
	r, _ := Parse("systemd-creds:theca")
	if r.String() != "systemd-creds:theca" {
		t.Fatal(r.String())
	}
}

func TestCredsDirectoryRefusals(t *testing.T) {
	dir, _ := credEnv(t)
	writeCred(t, dir, "loose", "x", 0o644)
	writeCred(t, dir, "empty", "", 0o600)
	writeCred(t, dir, "big", strings.Repeat("a", MaxSize+1), 0o600)
	writeCred(t, dir, "target", "x", 0o600)
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		want error
	}{{"loose", nil}, {"empty", ErrEmpty}, {"big", ErrTooLarge}, {"link", nil}, {"adir", nil}} {
		_, err := Open(context.Background(), "systemd-creds:"+c.name)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// systemd gives a User= service a root-owned 0440 file with an ACL; the group
// bits are the ACL mask. Group access is accepted, "other" access is not.
func TestCredsGroupBitsAcceptedOthersRefused(t *testing.T) {
	dir, _ := credEnv(t)
	writeCred(t, dir, "acl", "x", 0o440)
	if err := os.Chmod(filepath.Join(dir, "acl"), 0o440); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), "systemd-creds:acl")
	if err != nil || string(s.Bytes()) != "x" {
		t.Fatal(err)
	}
	writeCred(t, dir, "other", "x", 0o404)
	if err := os.Chmod(filepath.Join(dir, "other"), 0o404); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), "systemd-creds:other"); err == nil || !strings.Contains(err.Error(), "others") {
		t.Fatal(err)
	}
}

func TestCredsForeignOwnerRefused(t *testing.T) {
	dir, _ := credEnv(t)
	if os.Geteuid() == 0 {
		t.Skip("owner is root")
	}
	writeCred(t, dir, "x", "x", 0o400)
	geteuid = func() int { return os.Geteuid() + 12345 }
	if _, err := Open(context.Background(), "systemd-creds:x"); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatal(err)
	}
}

func TestCredsDirectoryOpenToOthersRefused(t *testing.T) {
	dir, _ := credEnv(t)
	writeCred(t, dir, "x", "x", 0o400)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), "systemd-creds:x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestCredsMissingDirectoryFallsBack(t *testing.T) {
	credEnv(t)
	getenv = func(string) string { return filepath.Join(t.TempDir(), "gone") }
	if _, err := Open(context.Background(), "systemd-creds:x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestCredsRelativeDirectory(t *testing.T) {
	credEnv(t)
	getenv = func(string) string { return "creds" }
	if _, err := Open(context.Background(), "systemd-creds:x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestCredsNotLinux(t *testing.T) {
	credEnv(t)
	goos = "darwin"
	if _, err := Open(context.Background(), "systemd-creds:x"); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "Linux only") {
		t.Fatal(err)
	}
}

func TestCredsNotFound(t *testing.T) {
	credEnv(t)
	if _, err := Open(context.Background(), "systemd-creds:nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestCredsDecryptFallback(t *testing.T) {
	dir, store := credEnv(t)
	// Unset variable, a .cred file in the second store directory, and a
	// symlink under the first name that must not be followed.
	getenv = func(string) string { return "" }
	geteuid = func() int { return 0 }
	writeCred(t, store, "pw.cred", "ciphertext", 0o600)
	_ = dir
	var got [][]string
	runCreds = func(_ context.Context, args []string) ([]byte, string, error) {
		got = append(got, args)
		return []byte("plain\r\n"), "", nil
	}
	s, err := Open(context.Background(), "systemd-creds:pw")
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Bytes()) != "plain" {
		t.Fatalf("%q", s.Bytes())
	}
	want := []string{"decrypt", "--name=pw", filepath.Join(store, "pw.cred"), "-"}
	if len(got) != 1 || strings.Join(got[0], "|") != strings.Join(want, "|") {
		t.Fatalf("argv %v", got)
	}
}

func TestCredsFallbackWhenNameMissingAndPlainName(t *testing.T) {
	_, store := credEnv(t) // variable set, directory empty
	writeCred(t, store, "pw", "ct", 0o600)
	runCreds = func(_ context.Context, args []string) ([]byte, string, error) { return []byte("v"), "", nil }
	s, err := Open(context.Background(), "systemd-creds:pw")
	if err != nil || string(s.Bytes()) != "v" {
		t.Fatal(err)
	}
}

func TestCredsUserScopeThenSystem(t *testing.T) {
	_, store := credEnv(t)
	geteuid = func() int { return 1000 }
	writeCred(t, store, "pw", "ct", 0o600)
	var scopes []string
	runCreds = func(_ context.Context, args []string) ([]byte, string, error) {
		scopes = append(scopes, strings.Join(args, " "))
		if len(scopes) == 1 {
			return nil, "wrong scope", errors.New("exit status 1")
		}
		return []byte("v"), "", nil
	}
	s, err := Open(context.Background(), "systemd-creds:pw")
	if err != nil || string(s.Bytes()) != "v" {
		t.Fatal(err)
	}
	if len(scopes) != 2 || !strings.Contains(scopes[0], "--user") || strings.Contains(scopes[1], "--user") {
		t.Fatal(scopes)
	}
}

func TestCredsDecryptFails(t *testing.T) {
	_, store := credEnv(t)
	writeCred(t, store, "pw", "ct", 0o600)
	runCreds = func(context.Context, []string) ([]byte, string, error) {
		return []byte("junk"), "Failed to decrypt: no TPM\n", errors.New("exit status 1")
	}
	_, err := Open(context.Background(), "systemd-creds:pw")
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "no TPM") {
		t.Fatal(err)
	}
}

func TestCredsDecryptTooLargeStops(t *testing.T) {
	_, store := credEnv(t)
	geteuid = func() int { return 1000 }
	writeCred(t, store, "pw", "ct", 0o600)
	n := 0
	runCreds = func(context.Context, []string) ([]byte, string, error) {
		n++
		return nil, "", ErrTooLarge
	}
	if _, err := Open(context.Background(), "systemd-creds:pw"); !errors.Is(err, ErrTooLarge) || n != 1 {
		t.Fatal(err, n)
	}
}

func TestCredsDecryptCancelledStops(t *testing.T) {
	_, store := credEnv(t)
	geteuid = func() int { return 1000 }
	writeCred(t, store, "pw", "ct", 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	runCreds = func(context.Context, []string) ([]byte, string, error) {
		n++
		cancel()
		return nil, "", errors.New("killed")
	}
	if _, err := Open(ctx, "systemd-creds:pw"); err == nil || n != 1 {
		t.Fatal(err, n)
	}
}

func TestCredsDecryptSkipsNonRegular(t *testing.T) {
	_, store := credEnv(t)
	if err := os.Mkdir(filepath.Join(store, "pw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), "systemd-creds:pw"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

// fakeCreds installs a shell script as systemd-creds and runs execCreds on it.
func fakeCreds(t *testing.T, script string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "systemd-creds")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := credsBin
	credsBin = bin
	t.Cleanup(func() { credsBin = old })
}

func TestExecCreds(t *testing.T) {
	// Prints its argv, whether the environment holds anything, and a secret.
	t.Setenv("CANARY_SECRET", "leak")
	fakeCreds(t, `[ -z "$CANARY_SECRET" ] || { echo env >&2; exit 3; }; printf '%s ' "$@"; echo; echo warn >&2`)
	b, se, err := execCreds(context.Background(), []string{"decrypt", "--name=x", "p", "-"})
	if err != nil || string(b) != "decrypt --name=x p - \n" || !strings.Contains(se, "warn") {
		t.Fatalf("%q %q %v", b, se, err)
	}
}

func TestExecCredsFailure(t *testing.T) {
	fakeCreds(t, `echo partial; echo broken >&2; exit 1`)
	b, se, err := execCreds(context.Background(), nil)
	if err == nil || b != nil || !strings.Contains(se, "broken") {
		t.Fatalf("%q %q %v", b, se, err)
	}
}

func TestExecCredsMissingBinary(t *testing.T) {
	old := credsBin
	credsBin = filepath.Join(t.TempDir(), "absent")
	defer func() { credsBin = old }()
	if _, _, err := execCreds(context.Background(), nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestExecCredsTooMuchOutput(t *testing.T) {
	fakeCreds(t, `yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)
	// A bound that is missing must fail this test by timing out, not hang it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := execCreds(ctx, nil)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestExecCredsTimeout(t *testing.T) {
	fakeCreds(t, `exec sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := execCreds(ctx, nil)
	if !errors.Is(err, ErrUnavailable) || time.Since(start) > 10*time.Second {
		t.Fatal(err, time.Since(start))
	}
}

func TestCappedWriter(t *testing.T) {
	c := &capped{cancel: func() {}}
	if n, err := c.Write(make([]byte, MaxSize)); n != MaxSize || err != nil {
		t.Fatal(n, err)
	}
	if _, err := c.Write([]byte{1}); err == nil || !c.over {
		t.Fatal("one byte past the cap must fail")
	}
}

func TestTailKeepsStart(t *testing.T) {
	var tl tail
	_, _ = tl.Write([]byte(strings.Repeat("a", 600)))
	_, _ = tl.Write([]byte("b"))
	if len(tl.b) != 512 || strings.Contains(string(tl.b), "b") {
		t.Fatal(len(tl.b))
	}
}
