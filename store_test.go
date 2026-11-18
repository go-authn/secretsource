package secretsource

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-freedesktop/secretservice"
	"github.com/go-macos/keychain"
)

const storeRef = "keepassxc:https://fido.invalid/yubikey-5c"
const storeURL = "https://fido.invalid/yubikey-5c"

// associated returns a fake KeePassXC with this machine already associated.
func associated(t *testing.T) *fakeKPX {
	t.Helper()
	f := newFake()
	f.crashOnURLLess = true // the model that kills KeePassXC on by-uuid/by-path lookups
	withFake(t, f)
	if _, err := Associate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStoreKeePassXCNewEntry(t *testing.T) {
	f := associated(t)
	ctx := context.Background()
	if err := Store(ctx, storeRef, []byte("246810"), StoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(f.setCalls) != 1 {
		t.Fatalf("set-login calls: %d", len(f.setCalls))
	}
	c := f.setCalls[0]
	if c["url"] != storeURL || c["submitUrl"] != storeURL || c["login"] != "fido.invalid" || c["password"] != "246810" {
		t.Errorf("set-login: %v", c)
	}
	if _, has := c["uuid"]; has {
		t.Error("a new entry carries no uuid")
	}
	if _, has := c["group"]; has {
		t.Error("no group asked: KeePassXC picks its own")
	}
	if f.crashed {
		t.Error("Store must never look an entry up by uuid or path")
	}
	// And it reads back through the normal path.
	s, err := Open(ctx, storeRef)
	if err != nil || string(s.Bytes()) != "246810" {
		t.Fatalf("%q %v", s.Bytes(), err)
	}
	// A custom login.
	f.entries = map[string][]map[string]any{}
	if err := Store(ctx, storeRef, []byte("1"), StoreOptions{Login: "yubikey"}); err != nil || f.setCalls[1]["login"] != "yubikey" {
		t.Errorf("%v %v", err, f.setCalls[1])
	}
}

func TestStoreKeePassXCExisting(t *testing.T) {
	f := associated(t)
	ctx := context.Background()
	f.entries[storeURL] = []map[string]any{{"login": "me", "password": "old", "name": "PIN", "group": "Keys", "uuid": "00112233445566778899aabbccddeeff"}}

	err := Store(ctx, storeRef, []byte("new"), StoreOptions{})
	if !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), `"PIN"`) || !strings.Contains(err.Error(), `"Keys"`) || len(f.setCalls) != 0 {
		t.Fatalf("%v (set-login calls %d)", err, len(f.setCalls))
	}
	if err := Store(ctx, storeRef, []byte("new"), StoreOptions{Replace: true, Login: "me"}); err != nil {
		t.Fatal(err)
	}
	if f.setCalls[0]["uuid"] != "00112233445566778899aabbccddeeff" {
		t.Errorf("the replace must name THAT entry by uuid: %v", f.setCalls[0])
	}
	if s, _ := Open(ctx, storeRef); string(s.Bytes()) != "new" {
		t.Errorf("not replaced: %q", s.Bytes())
	}
	// Unchanged values: KeePassXC says "error".
	if err := Store(ctx, storeRef, []byte("new"), StoreOptions{Replace: true, Login: "me"}); err == nil || !strings.Contains(err.Error(), "did not store") {
		t.Errorf("unchanged: %v", err)
	}
	// An entry with no user name cannot be updated that way.
	f.entries[storeURL][0]["login"] = ""
	if err := Store(ctx, storeRef, []byte("x"), StoreOptions{Replace: true}); err == nil {
		t.Error("no user name")
	}
	// --group names a place for a NEW entry only.
	if err := Store(ctx, storeRef, []byte("x"), StoreOptions{Replace: true, Group: "Keys"}); !errors.Is(err, ErrNoStore) {
		t.Errorf("group with replace: %v", err)
	}
	// An existing entry whose uuid is not hex is not sent back.
	f.entries[storeURL][0]["uuid"] = "zz"
	if err := Store(ctx, storeRef, []byte("x"), StoreOptions{Replace: true}); err == nil || !strings.Contains(err.Error(), "uuid") {
		t.Errorf("bad uuid: %v", err)
	}
	// Two entries: refused, named.
	f.entries[storeURL] = []map[string]any{
		{"login": "a", "password": "1", "name": "One", "group": "G1", "uuid": "11111111111111111111111111111111"},
		{"login": "b", "password": "2", "name": "Two", "group": "G2", "uuid": "22222222222222222222222222222222"},
	}
	n := len(f.setCalls)
	err = Store(ctx, storeRef, []byte("x"), StoreOptions{Replace: true})
	if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "1111") || !strings.Contains(err.Error(), `"Two"`) || len(f.setCalls) != n {
		t.Errorf("%v", err)
	}
	if f.crashed {
		t.Error("crash model tripped")
	}
}

func TestStoreKeePassXCGroupAndFailures(t *testing.T) {
	f := associated(t)
	ctx := context.Background()
	f.groups = []map[string]any{{"name": "Root", "uuid": "00000000000000000000000000000001", "children": []any{
		map[string]any{"name": "Keys", "uuid": "00000000000000000000000000000002", "children": []any{
			map[string]any{"name": "FIDO", "uuid": "00000000000000000000000000000003", "children": []any{}},
		}},
		map[string]any{"name": "Dup", "uuid": "00000000000000000000000000000004", "children": []any{}},
		map[string]any{"name": "Dup", "uuid": "00000000000000000000000000000005", "children": []any{}},
		map[string]any{"name": "Bad", "uuid": "nothex", "children": []any{}},
	}}}
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{Group: "Keys/FIDO"}); err != nil {
		t.Fatal(err)
	}
	c := f.setCalls[len(f.setCalls)-1]
	if c["group"] != "Keys/FIDO" || c["groupUuid"] != "00000000000000000000000000000003" {
		t.Errorf("group not passed: %v", c)
	}
	if es := f.entries[storeURL]; es[0]["group"] != "Keys/FIDO" {
		t.Errorf("%v", es)
	}
	f.entries = map[string][]map[string]any{}
	for _, g := range []struct {
		path string
		want error
	}{{"Nope", ErrNotFound}, {"Keys/Nope", ErrNotFound}, {"Dup", ErrAmbiguous}, {"Keys//FIDO", ErrNotFound}, {"/Keys", ErrNotFound}} {
		if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{Group: g.path}); !errors.Is(err, g.want) {
			t.Errorf("group %q: %v", g.path, err)
		}
	}
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{Group: "Bad"}); err == nil || !strings.Contains(err.Error(), "uuid") {
		t.Errorf("bad group uuid: %v", err)
	}
	f.groups = nil
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{Group: "Keys"}); err == nil {
		t.Error("no groups reply")
	}
	f.groups = []map[string]any{}
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{Group: "Keys"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("no root: %v", err)
	}

	// Failures of the protocol itself.
	f.groups = nil
	f.errs["get-logins"] = "6"
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{}); !errors.Is(err, ErrDenied) {
		t.Errorf("access refused: %v", err)
	}
	delete(f.errs, "get-logins")
	f.errs["set-login"] = "34"
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{}); err == nil || !strings.Contains(err.Error(), "error 34") {
		t.Errorf("set-login error: %v", err)
	}
	delete(f.errs, "set-login")
	f.setDeclines = true
	if err := Store(ctx, storeRef, []byte("pin"), StoreOptions{}); err == nil || !strings.Contains(err.Error(), "did not store") {
		t.Errorf("declined: %v", err)
	}
	// A URL with no host cannot name a login by itself.
	f.setDeclines = false
	if err := Store(ctx, "keepassxc:a://", []byte("pin"), StoreOptions{}); !errors.Is(err, ErrBadRef) || !strings.Contains(err.Error(), "--login") {
		t.Errorf("no host: %v", err)
	}
	if err := Store(ctx, "keepassxc:a://", []byte("pin"), StoreOptions{Login: "me"}); err != nil {
		t.Errorf("no host with --login: %v", err)
	}
}

func TestStoreKeePassXCNotAssociatedOrDown(t *testing.T) {
	f := newFake()
	withFake(t, f)
	if err := Store(context.Background(), storeRef, []byte("x"), StoreOptions{}); !errors.Is(err, ErrNotAssociated) {
		t.Errorf("%v", err)
	}
}

func TestSessionRefusesTheCrashingURLs(t *testing.T) {
	f := associated(t)
	s, err := openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := s.logins("keepassxc://by-path/Yubikey PIN"); !errors.Is(err, ErrBadRef) {
		t.Errorf("%v", err)
	}
	for _, a := range f.seen {
		if a == "get-logins" {
			t.Error("the lookup was sent")
		}
	}
}

func TestStoreArguments(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		ref    string
		secret []byte
		o      StoreOptions
		want   error
	}{
		{"nope", []byte("x"), StoreOptions{}, ErrBadRef},
		{storeRef, nil, StoreOptions{}, ErrEmpty},
		{storeRef, make([]byte, MaxSize+1), StoreOptions{}, ErrTooLarge},
		{"file:/tmp/x", []byte("x"), StoreOptions{}, ErrNoStore},
		{"keychain:a/b", []byte("x"), StoreOptions{Login: "me"}, ErrNoStore},
		{"secretservice:a/b", []byte("x"), StoreOptions{Group: "g"}, ErrNoStore},
		{"secretservice:Title=x", []byte("x"), StoreOptions{}, ErrNoStore},
	} {
		if err := Store(ctx, c.ref, c.secret, c.o); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.ref, err, c.want)
		}
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if err := Store(dead, "keychain:a/b", []byte("x"), StoreOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestStoreKV(t *testing.T) {
	ctx := context.Background()
	type store struct {
		scheme           string
		fakeGet          func(*testing.T, func(string, string) ([]byte, error))
		notFound, locked error
		set              *func(string, string, []byte) error
	}
	oldKCSet, oldSSSet := keychainSet, ssSet
	t.Cleanup(func() { keychainSet, ssSet = oldKCSet, oldSSSet })
	for _, st := range []store{
		{"keychain", fakeKeychain, keychain.ErrNotFound, &keychain.Error{Op: "get", Status: -25308}, &keychainSet},
		{"secretservice", fakeSecretService, secretservice.ErrNotFound, errors.New("unlock: boom"), &ssSet},
	} {
		t.Run(st.scheme, func(t *testing.T) {
			ref := st.scheme + ":fido/key"
			var gotS, gotA string
			var gotSecret []byte
			*st.set = func(s, a string, b []byte) error { gotS, gotA, gotSecret = s, a, append([]byte(nil), b...); return nil }

			// Absent: stored.
			st.fakeGet(t, func(string, string) ([]byte, error) { return nil, st.notFound })
			if err := Store(ctx, ref, []byte("246810"), StoreOptions{}); err != nil || gotS != "fido" || gotA != "key" || string(gotSecret) != "246810" {
				t.Fatalf("%v %q %q %q", err, gotS, gotA, gotSecret)
			}
			// Present: refused, then replaced on request (and the old value wiped).
			old := []byte("old-secret")
			st.fakeGet(t, func(string, string) ([]byte, error) { return old, nil })
			gotSecret = nil
			if err := Store(ctx, ref, []byte("new"), StoreOptions{}); !errors.Is(err, ErrExists) || gotSecret != nil {
				t.Fatalf("%v", err)
			}
			if err := Store(ctx, ref, []byte("new"), StoreOptions{Replace: true}); err != nil || string(gotSecret) != "new" {
				t.Fatalf("%v %q", err, gotSecret)
			}
			if string(old) == "old-secret" {
				t.Error("the existing secret that was read to test for presence must be wiped")
			}
			// The manager is locked / refuses.
			st.fakeGet(t, func(string, string) ([]byte, error) { return nil, st.locked })
			if err := Store(ctx, ref, []byte("x"), StoreOptions{}); err == nil {
				t.Error("locked")
			}
			// The write fails.
			st.fakeGet(t, func(string, string) ([]byte, error) { return nil, st.notFound })
			*st.set = func(string, string, []byte) error { return errors.New("refused") }
			if err := Store(ctx, ref, []byte("x"), StoreOptions{}); err == nil || !strings.Contains(err.Error(), "refused") {
				t.Errorf("write failure: %v", err)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	for _, n := range []int{1, 6, 24, MaxGenerate} {
		b, err := Generate(n)
		if err != nil || len(b) != n {
			t.Fatalf("%d: %v %d", n, err, len(b))
		}
		for _, c := range b {
			if !strings.ContainsRune(alphabet, rune(c)) {
				t.Fatalf("%q outside the alphabet", c)
			}
		}
	}
	// Two draws differ (2^-140 chance of a false failure).
	a, _ := Generate(24)
	b, _ := Generate(24)
	if string(a) == string(b) {
		t.Error("two draws are equal")
	}
	for _, n := range []int{0, -1, MaxGenerate + 1} {
		if _, err := Generate(n); err == nil {
			t.Errorf("%d accepted", n)
		}
	}
	old := randReader
	t.Cleanup(func() { randReader = old })
	randReader = &failingReader{}
	if b, err := Generate(8); err == nil || b != nil {
		t.Errorf("no entropy: %v", err)
	}
}

func TestResolveGroup(t *testing.T) {
	tree := func(s string) groupTree {
		var g groupTree
		if err := json.Unmarshal([]byte(s), &g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := tree(`{"groups":{"groups":[{"name":"R","uuid":"` + strings.Repeat("0", 32) + `","children":[{"name":"A","uuid":"` + strings.Repeat("a", 32) + `","children":[]}]}]}}`)
	if id, err := resolveGroup(g, "A"); err != nil || id != strings.Repeat("a", 32) {
		t.Errorf("%q %v", id, err)
	}
	if _, err := resolveGroup(g, "R"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the root is not addressed by name: %v", err)
	}
	if _, err := resolveGroup(tree(`{}`), "A"); err == nil {
		t.Error("empty tree")
	}
	if _, err := resolveGroup(tree(`{"groups":{"groups":[{},{}]}}`), "A"); err == nil {
		t.Error("two roots")
	}
}

func FuzzResolveGroup(f *testing.F) {
	f.Add([]byte(`{"groups":{"groups":[{"name":"R","uuid":"00000000000000000000000000000000","children":[{"name":"A","uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","children":[]}]}]}}`), "A")
	f.Add([]byte(`{"groups":{"groups":[{"name":"A","children":[{"name":"A","children":[{"name":"A"}]}]}]}}`), "A/A")
	f.Add([]byte(`{"groups":null}`), "")
	f.Add([]byte(`[`), "x")
	f.Fuzz(func(t *testing.T, data []byte, path string) {
		var g groupTree
		if json.Unmarshal(data, &g) != nil {
			return
		}
		id, err := resolveGroup(g, path)
		if err == nil && !validUUID(id) {
			t.Fatalf("returned %q without error", id)
		}
	})
}
