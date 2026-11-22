package secretflag

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var dst string
	cmd := &cobra.Command{Use: "x", SilenceUsage: true, RunE: func(*cobra.Command, []string) error { return nil }}
	b := Add(cmd, "token", &dst, "a token")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.Flags().SetOutput(&errb)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return "", errb.String(), err
	}
	err := Resolve(context.Background(), b)
	return dst, errb.String(), err
}

func runStd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var dst string
	var warn bytes.Buffer
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	b := AddStd(fs, &warn, "token", &dst, "a token", "t")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	err := Resolve(context.Background(), b)
	return dst, warn.String(), err
}

func tokFile(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file: refuses a temp file whose inherited DACL grants a non-owner; that refusal is secretsource's own tested behaviour")
	}
	p := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func withOpen(t *testing.T, f func(context.Context, string) ([]byte, error)) {
	t.Helper()
	old := open
	t.Cleanup(func() { open = old })
	open = f
}

func TestCobraPlainWorksAndWarns(t *testing.T) {
	got, stderr, err := run(t, "--token", "abc")
	if err != nil || got != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "--token-from") {
		t.Fatalf("no deprecation warning: %q", stderr)
	}
}

func TestCobraFromFile(t *testing.T) {
	got, stderr, err := run(t, "--token-from", "file:"+tokFile(t))
	if err != nil || got != "s3cret" || strings.Contains(stderr, "deprecated") {
		t.Fatalf("got %q, %q, %v", got, stderr, err)
	}
}

func TestCobraExclusiveAndNeither(t *testing.T) {
	if _, _, err := run(t, "--token", "a", "--token-from", "file:/x"); err == nil {
		t.Fatal("both flags accepted")
	}
	if got, _, err := run(t); err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestStdPlainAndAliasWarn(t *testing.T) {
	for _, a := range []string{"-token", "-t", "--token"} {
		got, warn, err := runStd(t, a, "abc")
		if err != nil || got != "abc" {
			t.Fatalf("%s: got %q, %v", a, got, err)
		}
		if !strings.Contains(warn, "deprecated") || !strings.Contains(warn, "--token-from") {
			t.Fatalf("%s: no warning: %q", a, warn)
		}
	}
}

func TestStdFromFile(t *testing.T) {
	got, warn, err := runStd(t, "-token-from", "file:"+tokFile(t))
	if err != nil || got != "s3cret" || warn != "" {
		t.Fatalf("got %q, %q, %v", got, warn, err)
	}
}

func TestStdExclusive(t *testing.T) {
	for _, a := range [][]string{{"-token", "a", "-token-from", "x:y"}, {"-t", "a", "-token-from", "x:y"}} {
		withOpen(t, func(context.Context, string) ([]byte, error) { t.Fatal("opened despite exclusivity"); return nil, nil })
		if _, _, err := runStd(t, a...); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("%v: err = %v", a, err)
		}
	}
}

func TestStdNeitherGiven(t *testing.T) {
	got, warn, err := runStd(t)
	if err != nil || got != "" || warn != "" {
		t.Fatalf("got %q, %q, %v", got, warn, err)
	}
}

func TestStdNilWarnDiscards(t *testing.T) {
	var dst string
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	b := AddStd(fs, nil, "token", &dst, "a token")
	if err := fs.Parse([]string{"-token", "v"}); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(context.Background(), b); err != nil || dst != "v" {
		t.Fatalf("%q %v", dst, err)
	}
}

func TestOpenErrorNamesTheFlagNotTheSecret(t *testing.T) {
	_, _, err := run(t, "--token-from", "file:/nonexistent/zzz")
	if err == nil || !strings.Contains(err.Error(), "--token-from") || strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptySecretRefused(t *testing.T) {
	withOpen(t, func(context.Context, string) ([]byte, error) { return []byte("\r\n"), nil })
	if _, _, err := run(t, "--token-from", "x:y"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := runStd(t, "-token-from", "x:y"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("std err = %v", err)
	}
}

func TestOpenFailurePropagates(t *testing.T) {
	want := errors.New("boom")
	withOpen(t, func(context.Context, string) ([]byte, error) { return nil, want })
	if _, _, err := run(t, "--token-from", "x:y"); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretIsNotKeptInTheOpenBuffer(t *testing.T) {
	buf := []byte("zzz\n")
	withOpen(t, func(context.Context, string) ([]byte, error) { return buf, nil })
	if got, _, err := run(t, "--token-from", "x:y"); err != nil || got != "zzz" {
		t.Fatalf("%q %v", got, err)
	}
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("raw buffer not cleared: %q", buf)
	}
}
