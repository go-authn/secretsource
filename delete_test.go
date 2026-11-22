package secretsource

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/go-freedesktop/secretservice"
	"github.com/go-macos/keychain"
)

func TestDeleteArguments(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		ref  string
		want error
	}{
		{"nope", ErrBadRef},
		{"file:/tmp/x", ErrNoDelete},
		{"systemd-creds:pin", ErrNoDelete},
		{"secretservice:Title=x", ErrNoDelete},
	} {
		if err := Delete(ctx, c.ref); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.ref, err, c.want)
		}
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if err := Delete(dead, "keychain:a/b"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestDeleteKV(t *testing.T) {
	ctx := context.Background()
	oldKC, oldSS := keychainDelete, ssDelete
	t.Cleanup(func() { keychainDelete, ssDelete = oldKC, oldSS })
	type store struct {
		scheme string
		// probe installs the lookup Delete makes and returns what service/account it asked for.
		probe            func(*testing.T, func() ([]byte, error)) *[2]string
		del              *func(string, string) error
		notFound, locked error
		ambiguous        error
	}
	probeKC := func(t *testing.T, fn func() ([]byte, error)) *[2]string {
		var got [2]string
		fakeKeychain(t, func(s, a string) ([]byte, error) { got = [2]string{s, a}; return fn() })
		return &got
	}
	probeSS := func(t *testing.T, fn func() ([]byte, error)) *[2]string {
		var got [2]string
		fakeSecretServiceAttrs(t, func(m map[string]string) ([]byte, error) {
			if len(m) != 2 {
				t.Errorf("attributes: %v", m)
			}
			got = [2]string{m["service"], m["account"]}
			return fn()
		})
		return &got
	}
	for _, st := range []store{
		{"keychain", probeKC, &keychainDelete, keychain.ErrNotFound, &keychain.Error{Op: "get", Status: -25308}, nil},
		{"secretservice", probeSS, &ssDelete, secretservice.ErrNotFound, errors.New("unlock: boom"), secretservice.ErrAmbiguous},
	} {
		t.Run(st.scheme, func(t *testing.T) {
			ref := st.scheme + ":fido/key"
			var calls int
			var delS, delA string
			*st.del = func(s, a string) error { calls++; delS, delA = s, a; return nil }

			// Present: deleted by service and account, and the value read to find it is wiped.
			old := []byte("old-secret")
			got := st.probe(t, func() ([]byte, error) { return old, nil })
			if err := Delete(ctx, ref); err != nil || calls != 1 || delS != "fido" || delA != "key" || *got != [2]string{"fido", "key"} {
				t.Fatalf("%v calls=%d %q %q %v", err, calls, delS, delA, *got)
			}
			if string(old) == "old-secret" {
				t.Error("the value read to test for presence must be wiped")
			}

			// Absent: both ErrNotFound and fs.ErrNotExist, nothing deleted.
			calls = 0
			st.probe(t, func() ([]byte, error) { return nil, st.notFound })
			err := Delete(ctx, ref)
			if !errors.Is(err, ErrNotFound) || !errors.Is(err, fs.ErrNotExist) || calls != 0 {
				t.Errorf("absent: %v calls=%d", err, calls)
			}
			if err != nil && strings.Contains(err.Error(), "old-secret") {
				t.Error("the secret leaked into an error")
			}

			// Several items: refused, nothing deleted.
			if st.ambiguous != nil {
				st.probe(t, func() ([]byte, error) { return nil, st.ambiguous })
				if err := Delete(ctx, ref); !errors.Is(err, ErrAmbiguous) || calls != 0 {
					t.Errorf("ambiguous: %v calls=%d", err, calls)
				}
			}

			// The manager is locked / refuses: nothing deleted.
			st.probe(t, func() ([]byte, error) { return nil, st.locked })
			if err := Delete(ctx, ref); err == nil || errors.Is(err, fs.ErrNotExist) || calls != 0 {
				t.Errorf("locked: %v calls=%d", err, calls)
			}

			// The delete itself fails.
			st.probe(t, func() ([]byte, error) { return []byte("x"), nil })
			*st.del = func(string, string) error { return errors.New("refused") }
			if err := Delete(ctx, ref); err == nil || !strings.Contains(err.Error(), "refused") {
				t.Errorf("delete failure: %v", err)
			}

			// A manager that never answers is given up on at the deadline.
			block := make(chan struct{})
			t.Cleanup(func() { close(block) })
			st.probe(t, func() ([]byte, error) { <-block; return nil, nil })
			short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			if err := Delete(short, ref); !errors.Is(err, ErrUnavailable) {
				t.Errorf("deadline: %v", err)
			}
		})
	}
}

func TestDeleteKeePassXC(t *testing.T) {
	f := associated(t)
	ctx := context.Background()
	const uuid1 = "00112233445566778899aabbccddeeff"

	// Absent.
	err := Delete(ctx, storeRef)
	if !errors.Is(err, ErrNotFound) || !errors.Is(err, fs.ErrNotExist) || len(f.deleteCalls) != 0 {
		t.Fatalf("absent: %v", err)
	}

	// One entry: deleted by the uuid KeePassXC reported, found by URL.
	f.entries[storeURL] = []map[string]any{{"login": "me", "password": "s3cret", "name": "PIN", "group": "Keys", "uuid": uuid1}}
	if err := Delete(ctx, storeRef); err != nil {
		t.Fatal(err)
	}
	if len(f.deleteCalls) != 1 || f.deleteCalls[0]["uuid"] != uuid1 {
		t.Fatalf("delete-entry: %v", f.deleteCalls)
	}
	if len(f.entries[storeURL]) != 0 || f.crashed {
		t.Errorf("entries %v crashed %v", f.entries[storeURL], f.crashed)
	}
	for k, v := range f.deleteCalls[0] {
		if s, _ := v.(string); strings.Contains(s, "s3cret") {
			t.Errorf("delete-entry carries the password in %q", k)
		}
	}
	// And it is gone: a second delete is "not found".
	if err := Delete(ctx, storeRef); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("second delete: %v", err)
	}

	// Two entries: refused, named, nothing deleted.
	f.entries[storeURL] = []map[string]any{
		{"login": "a", "password": "1", "name": "One", "group": "G1", "uuid": "11111111111111111111111111111111"},
		{"login": "b", "password": "2", "name": "Two", "group": "G2", "uuid": "22222222222222222222222222222222"},
	}
	n := len(f.deleteCalls)
	err = Delete(ctx, storeRef)
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), `"Two"`) || len(f.deleteCalls) != n || len(f.entries[storeURL]) != 2 {
		t.Errorf("ambiguous: %v", err)
	}

	// An entry whose uuid is not hex is never sent back.
	f.entries[storeURL] = []map[string]any{{"login": "a", "password": "1", "name": "One", "group": "G", "uuid": "zz"}}
	if err := Delete(ctx, storeRef); err == nil || !strings.Contains(err.Error(), "uuid") || len(f.deleteCalls) != n {
		t.Errorf("bad uuid: %v", err)
	}

	// The person answers No to KeePassXC's dialog.
	f.entries[storeURL] = []map[string]any{{"login": "a", "password": "1", "name": "One", "group": "G", "uuid": uuid1}}
	f.deleteDeclines = true
	if err := Delete(ctx, storeRef); err == nil || !errors.Is(err, errNotSucceeded) || !strings.Contains(err.Error(), "did not delete") || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("declined: %v", err)
	}
	f.deleteDeclines = false

	// KeePassXC answers with an error code.
	f.errs["delete-entry"] = "34"
	if err := Delete(ctx, storeRef); err == nil || errors.Is(err, errNotSucceeded) {
		t.Errorf("delete-entry error: %v", err)
	}
	delete(f.errs, "delete-entry")
	f.errs["get-logins"] = "34"
	if err := Delete(ctx, storeRef); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("get-logins error: %v", err)
	}
	delete(f.errs, "get-logins")

	// A success reply that lists no entry is "not found" as well.
	f.tamper = func(action string, _ map[string]string, inner map[string]any) {
		if action == "get-logins" {
			inner["entries"] = []any{}
		}
	}
	if err := Delete(ctx, storeRef); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty success reply: %v", err)
	}
	f.tamper = nil

	// Not associated: a delete never creates trust.
	withFake(t, newFake())
	if err := Delete(ctx, storeRef); !errors.Is(err, ErrNotAssociated) {
		t.Errorf("not associated: %v", err)
	}
}
