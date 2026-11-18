package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

type stored struct {
	ref    string
	secret string
	o      secretsource.StoreOptions
}

func fakeStore(t *testing.T) *[]stored {
	t.Helper()
	var calls []stored
	old := store
	t.Cleanup(func() { store = old })
	store = func(_ context.Context, ref string, secret []byte, o secretsource.StoreOptions) error {
		calls = append(calls, stored{ref, string(secret), o})
		return nil
	}
	return &calls
}

func runIn(stdin string, args ...string) (out, errOut string, err error) {
	c := RootCmd()
	var o, e bytes.Buffer
	c.SetOut(&o)
	c.SetErr(&e)
	c.SetIn(strings.NewReader(stdin))
	c.SetArgs(args)
	err = c.Execute()
	return o.String(), e.String(), err
}

func TestStoreFromStdin(t *testing.T) {
	calls := fakeStore(t)
	out, _, err := runIn("246810\n", "store", "keepassxc:https://fido.invalid/k", "--group", "Keys/FIDO", "--login", "me", "--replace")
	if err != nil || len(*calls) != 1 {
		t.Fatalf("%v %v", err, calls)
	}
	c := (*calls)[0]
	if c.ref != "keepassxc:https://fido.invalid/k" || c.secret != "246810" || c.o.Group != "Keys/FIDO" || c.o.Login != "me" || !c.o.Replace {
		t.Errorf("%+v", c)
	}
	if strings.Contains(out, "246810") || !strings.Contains(out, "Stored in") {
		t.Errorf("output %q", out)
	}
	for in, want := range map[string]string{"pin\r\n": "pin", "pin": "pin", "a\nb\n": "a\nb", "\n": "", "": ""} {
		*calls = nil
		if _, _, err := runIn(in, "store", "keychain:a/b"); err != nil || (*calls)[0].secret != want {
			t.Errorf("%q: %v %+v", in, err, *calls)
		}
	}
	// Too long.
	if _, _, err := runIn(strings.Repeat("x", secretsource.MaxSize+1), "store", "keychain:a/b"); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("long: %v", err)
	}
}

func TestStoreFromTheTerminal(t *testing.T) {
	calls := fakeStore(t)
	oldT, oldP := isTerminal, readPassword
	t.Cleanup(func() { isTerminal, readPassword = oldT, oldP })
	isTerminal = func(int) bool { return true }
	var answers []string
	readPassword = func(int) ([]byte, error) {
		if len(answers) == 0 {
			return nil, errors.New("terminal closed")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run := func(args ...string) (string, error) {
		c := RootCmd()
		var o, e bytes.Buffer
		c.SetOut(&o)
		c.SetErr(&e)
		c.SetIn(f)
		c.SetArgs(args)
		err := c.Execute()
		return e.String(), err
	}
	answers = []string{"secret", "secret"}
	if e, err := run("store", "keychain:a/b"); err != nil || (*calls)[0].secret != "secret" || !strings.Contains(e, "Again") {
		t.Fatalf("%v %v %q", err, *calls, e)
	}
	answers = []string{"one", "two"}
	if _, err := run("store", "keychain:a/b"); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Errorf("mismatch: %v", err)
	}
	answers = []string{"one"}
	if _, err := run("store", "keychain:a/b"); err == nil {
		t.Error("second read fails")
	}
	answers = nil
	if _, err := run("store", "keychain:a/b"); err == nil {
		t.Error("first read fails")
	}
}

func TestStoreGenerate(t *testing.T) {
	calls := fakeStore(t)
	out, _, err := runIn("ignored stdin", "store", "keychain:a/b", "--generate", "24")
	if err != nil || len((*calls)[0].secret) != 24 || strings.Contains(out, (*calls)[0].secret) || !strings.Contains(out, "nothing was printed") {
		t.Fatalf("%v %+v %q", err, *calls, out)
	}
	if _, _, err := runIn("", "store", "keychain:a/b", "--generate", "0"); err == nil {
		t.Error("--generate 0")
	}
}

func TestStoreRefusals(t *testing.T) {
	calls := fakeStore(t)
	if _, _, err := runIn("x", "store", "keepassxc:https://a.invalid/b", "--title", "My PIN"); err == nil || !strings.Contains(err.Error(), "BrowserService.cpp:891") || len(*calls) != 0 {
		t.Errorf("--title: %v", err)
	}
	if _, _, err := runIn("x", "store"); err == nil {
		t.Error("no reference")
	}
	store = func(context.Context, string, []byte, secretsource.StoreOptions) error { return secretsource.ErrExists }
	if _, _, err := runIn("x", "store", "keychain:a/b"); !errors.Is(err, secretsource.ErrExists) {
		t.Errorf("%v", err)
	}
	// The real library refuses a plaintext file.
	store = secretsource.Store
	if _, _, err := runIn("x", "store", "file:/tmp/never"); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("file: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("stdin broke") }

func TestStoreStdinFailure(t *testing.T) {
	calls := fakeStore(t)
	c := RootCmd()
	c.SetIn(failingReader{})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"store", "keychain:a/b"})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "broke") || len(*calls) != 0 {
		t.Errorf("%v", err)
	}
}
