package secretflag

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func fakeRefs(t *testing.T, m map[string]string) {
	t.Helper()
	withOpen(t, func(_ context.Context, ref string) ([]byte, error) {
		v, ok := m[ref]
		if !ok {
			return nil, errors.New("no such reference")
		}
		return []byte(v), nil
	})
}

func fromCmd() *cobra.Command {
	return &cobra.Command{Use: "x", SilenceUsage: true, RunE: func(*cobra.Command, []string) error { return nil }}
}

func TestAddFromResolvesTrimsAndHasNoPlainTwin(t *testing.T) {
	fakeRefs(t, map[string]string{"r:a": "s3cret\r\n"})
	var dst string
	cmd := fromCmd()
	b := AddFrom(cmd, "key", &dst, "a key")
	if cmd.Flags().Lookup("key") != nil {
		t.Fatal("a plain --key flag exists: its value would show in ps")
	}
	cmd.SetArgs([]string{"--key-from", "r:a"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(context.Background(), b); err != nil || dst != "s3cret" {
		t.Fatalf("got %q, %v", dst, err)
	}
}

func TestAddFromUnsetLeavesDestination(t *testing.T) {
	dst := "kept"
	cmd := fromCmd()
	b := AddFrom(cmd, "key", &dst, "a key")
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(context.Background(), b); err != nil || dst != "kept" {
		t.Fatalf("got %q, %v", dst, err)
	}
}

func TestAddFromEmptyAndMissingAreErrorsWithoutValue(t *testing.T) {
	fakeRefs(t, map[string]string{"r:empty": "\n"})
	for _, ref := range []string{"r:empty", "r:none"} {
		var dst string
		cmd := fromCmd()
		b := AddFrom(cmd, "key", &dst, "a key")
		cmd.SetArgs([]string{"--key-from", ref})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		err := Resolve(context.Background(), b)
		if err == nil || !strings.Contains(err.Error(), "--key-from") || dst != "" {
			t.Fatalf("%s: err = %v dst = %q", ref, err, dst)
		}
		if (ref == "r:empty") != errors.Is(err, errEmpty) {
			t.Fatalf("%s: wrong cause: %v", ref, err)
		}
	}
}

func TestAddFromListKeepsOrderAndFailsOnBadRef(t *testing.T) {
	fakeRefs(t, map[string]string{"r:1": "one", "r:2": "two", "r:empty": ""})
	var dst []string
	cmd := fromCmd()
	b := AddFromList(cmd, "old-key", &dst, "old keys")
	if cmd.Flags().Lookup("old-key") != nil {
		t.Fatal("a plain --old-key flag exists")
	}
	cmd.SetArgs([]string{"--old-key-from", "r:1", "--old-key-from", "r:2"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(context.Background(), b); err != nil || len(dst) != 2 || dst[0] != "one" || dst[1] != "two" {
		t.Fatalf("got %v, %v", dst, err)
	}
	for _, bad := range []string{"r:none", "r:empty"} {
		var out []string
		cmd = fromCmd()
		b = AddFromList(cmd, "old-key", &out, "old keys")
		cmd.SetArgs([]string{"--old-key-from", "r:1", "--old-key-from", bad})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if err := Resolve(context.Background(), b); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	// No reference given: dst untouched.
	var none []string
	cmd = fromCmd()
	b = AddFromList(cmd, "old-key", &none, "old keys")
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := Resolve(context.Background(), b); err != nil || len(none) != 0 {
		t.Fatalf("got %v, %v", none, err)
	}
}
