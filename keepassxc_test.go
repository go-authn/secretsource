package secretsource

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-freedesktop/secretservice"
	"github.com/go-macos/keychain"
	"golang.org/x/crypto/nacl/box"
)

// fakeKPX is a KeePassXC: the server half of BrowserAction/BrowserMessageBuilder.
type fakeKPX struct {
	hash    string
	keys    map[string]string // association id -> identification key
	newID   string            // the name the person gives at associate; "" cancels
	entries map[string][]map[string]any
	errs    map[string]string // action -> errorCode to answer with
	silent  map[string]bool   // actions never answered
	// tamper edits a reply before it is sent.
	tamper   func(action string, outer map[string]string, inner map[string]any)
	preamble string // written before every reply (unsolicited notices)
	drip     bool   // replies go out one byte per write
	closeOn  string // close the socket instead of answering this action
	seen     []string
	got      map[string]map[string]any // last inner request per action
	// crashOnURLLess models KeePassXC 2.8.0: a get-logins for keepassxc://by-...
	// that finds an entry without a URL kills the process.
	crashOnURLLess bool
	crashed        bool
	// groups is the tree get-database-groups answers with (nil: error 16).
	groups []map[string]any
	// setCalls are the inner set-login requests; setDeclines makes it answer "error".
	setCalls    []map[string]any
	setDeclines bool
	nextUUID    int
}

func newFake() *fakeKPX {
	return &fakeKPX{
		hash: "abc123", keys: map[string]string{}, newID: "laptop",
		entries: map[string][]map[string]any{}, errs: map[string]string{}, silent: map[string]bool{},
		got: map[string]map[string]any{},
	}
}

func (f *fakeKPX) dial(context.Context) (net.Conn, error) {
	c, s := net.Pipe()
	go f.serve(s)
	return c, nil
}

func (f *fakeKPX) serve(s net.Conn) {
	defer s.Close()
	var buf []byte
	var clientPub, srvPub, srvPriv = new([32]byte), (*[32]byte)(nil), (*[32]byte)(nil)
	write := func(m map[string]string) {
		b, _ := json.Marshal(m)
		b = append([]byte(f.preamble), b...)
		if f.drip {
			for _, c := range b {
				if _, err := s.Write([]byte{c}); err != nil {
					return
				}
			}
			return
		}
		_, _ = s.Write(b)
	}
	for {
		var req map[string]string
		for {
			if o, n, err := decodeFrame(buf); err == nil {
				_ = o
				if jerr := json.Unmarshal(buf[bytes.IndexByte(buf, '{'):n], &req); jerr != nil {
					return
				}
				buf = buf[n:]
				break
			}
			chunk := make([]byte, 4096)
			m, err := s.Read(chunk)
			buf = append(buf, chunk[:m]...)
			if m == 0 && err != nil {
				return
			}
		}
		action := req["action"]
		f.seen = append(f.seen, action)
		if f.closeOn == action {
			return
		}
		if f.silent[action] {
			continue
		}
		if code, ok := f.errs[action]; ok {
			write(map[string]string{"action": action, "errorCode": code, "error": "fake error " + code})
			continue
		}
		nonceB, _ := base64.StdEncoding.DecodeString(req["nonce"])
		var nonce [24]byte
		copy(nonce[:], nonceB)
		inc := incrementNonce(nonce)
		if action == "change-public-keys" {
			pk, _ := base64.StdEncoding.DecodeString(req["publicKey"])
			copy(clientPub[:], pk)
			srvPub, srvPriv, _ = box.GenerateKey(rand.Reader)
			out := map[string]string{"action": action, "publicKey": b64(srvPub[:]), "nonce": b64(inc[:]), "version": "2.7.9", "success": "true"}
			if f.tamper != nil {
				f.tamper(action, out, nil)
			}
			write(out)
			continue
		}
		raw, _ := base64.StdEncoding.DecodeString(req["message"])
		plain, ok := box.Open(nil, raw, &nonce, clientPub, srvPriv)
		if !ok {
			write(map[string]string{"action": action, "errorCode": "4", "error": "cannot decrypt"})
			continue
		}
		var in map[string]any
		_ = json.Unmarshal(plain, &in)
		f.got[action] = in
		if req["triggerUnlock"] != "true" {
			f.errs["_no_trigger"] = action
		}
		inner := map[string]any{"success": "true", "nonce": b64(inc[:]), "version": "2.7.9", "hash": f.hash}
		switch action {
		case "associate":
			if f.newID == "" {
				write(map[string]string{"action": action, "errorCode": "6", "error": "cancelled"})
				continue
			}
			f.keys[f.newID] = in["idKey"].(string)
			inner["id"] = f.newID
		case "test-associate":
			id, _ := in["id"].(string)
			if k, ok := f.keys[id]; !ok || k != in["key"] {
				write(map[string]string{"action": action, "errorCode": "8", "error": "association failed"})
				continue
			}
			inner["id"] = id
		case "get-database-groups":
			if f.groups == nil {
				write(map[string]string{"action": action, "errorCode": "16", "error": "no groups found"})
				continue
			}
			inner["groups"] = map[string]any{"groups": f.groups}
		case "set-login":
			// BrowserAction::handleSetLogin: no uuid adds, a uuid updates (BrowserService::updateEntry).
			f.setCalls = append(f.setCalls, in)
			url, _ := in["url"].(string)
			login, _ := in["login"].(string)
			pw, _ := in["password"].(string)
			uuid, _ := in["uuid"].(string)
			ok := !f.setDeclines
			if uuid == "" {
				f.nextUUID++
				grp, _ := in["group"].(string)
				if grp == "" {
					grp = "KeePassXC-Browser Passwords"
				}
				f.entries[url] = append(f.entries[url], map[string]any{
					"login": login, "password": pw, "name": "added", "group": grp,
					"uuid": fmt.Sprintf("%032x", f.nextUUID),
				})
			} else {
				ok = false
				for _, e := range f.entries[url] {
					if e["uuid"] != uuid || f.setDeclines {
						continue
					}
					// updateEntry: refuses an entry with no user name, and an update that changes nothing.
					if e["login"] != "" && (e["login"] != login || e["password"] != pw) {
						e["login"], e["password"] = login, pw
						ok = true
					}
				}
			}
			inner["count"], inner["entries"] = nil, nil
			if ok {
				inner["error"] = "success"
			} else {
				inner["error"] = "error"
			}
		case "get-logins":
			url, _ := in["url"].(string)
			es := f.entries[url]
			if f.crashOnURLLess && len(es) > 0 && strings.HasPrefix(url, "keepassxc://by-") {
				f.crashed = true
				return // SIGSEGV in sortPriority: the socket just closes
			}
			if len(es) == 0 {
				write(map[string]string{"action": action, "errorCode": "15", "error": "no logins found"})
				continue
			}
			inner["count"] = len(es)
			inner["entries"] = es
		}
		out := map[string]string{"action": action, "nonce": b64(inc[:])}
		if f.tamper != nil {
			f.tamper(action, out, inner)
		}
		pb, _ := json.Marshal(inner)
		if _, ok := out["_raw"]; ok {
			pb = []byte(out["_raw"])
			delete(out, "_raw")
		}
		if _, ok := out["message"]; !ok {
			out["message"] = b64(box.Seal(nil, pb, &inc, clientPub, srvPriv))
		}
		write(out)
	}
}

// withFake installs the fake KeePassXC and an in-memory association store.
func withFake(t *testing.T, f *fakeKPX) *memStore {
	t.Helper()
	oldDial, oldStore := keepassxcDial, newAssocStore
	keepassxcDial = f.dial
	ms := &memStore{m: map[string]assoc{}}
	newAssocStore = func() assocStore { return ms }
	t.Cleanup(func() { keepassxcDial, newAssocStore = oldDial, oldStore })
	return ms
}

type memStore struct {
	m       map[string]assoc
	saveErr error
}

func (s *memStore) load(h string) (assoc, error) {
	if a, ok := s.m[h]; ok {
		return a, nil
	}
	return assoc{}, notAssociated(h)
}

func (s *memStore) save(h string, a assoc) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.m[h] = a
	return nil
}

func entry(pw string) map[string]any {
	return map[string]any{"login": "u", "name": "Yubikey PIN", "password": pw, "uuid": "00112233445566778899aabbccddeeff"}
}

const refURL = "keepassxc:https://theca.invalid/vault"
const urlURL = "https://theca.invalid/vault"

func TestKeePassXCAssociateThenOpen(t *testing.T) {
	f := newFake()
	f.entries[urlURL] = []map[string]any{entry("246810")}
	ms := withFake(t, f)
	ctx := context.Background()

	// Not associated yet: a lookup never creates trust.
	if _, err := Open(ctx, refURL); !errors.Is(err, ErrNotAssociated) || !strings.Contains(err.Error(), "associate") {
		t.Fatalf("before association: %v", err)
	}
	a, err := Associate(ctx)
	if err != nil || a.ID != "laptop" || a.Database != "abc123" {
		t.Fatalf("associate: %+v %v", a, err)
	}
	if ms.m["abc123"].ID != "laptop" || ms.m["abc123"].Key != f.keys["laptop"] {
		t.Fatalf("the association was not kept: %+v vs %v", ms.m, f.keys)
	}
	s, err := Open(ctx, refURL)
	if err != nil || string(s.Bytes()) != "246810" {
		t.Fatalf("open: %q %v", s.Bytes(), err)
	}
	s.Close()
	if f.errs["_no_trigger"] != "" {
		t.Errorf("%s was sent without triggerUnlock", f.errs["_no_trigger"])
	}
	// The request named the entry by KeePassXC's own URL, with the association.
	keys := f.got["get-logins"]["keys"].([]any)[0].(map[string]any)
	if keys["id"] != "laptop" || keys["key"] != f.keys["laptop"] {
		t.Errorf("keys %v", keys)
	}
	// A URL travels exactly as written.
	f.entries["theca://vault"] = []map[string]any{entry("pw")}
	if s, err := Open(ctx, "keepassxc:theca://vault"); err != nil || string(s.Bytes()) != "pw" || f.got["get-logins"]["url"] != "theca://vault" {
		t.Errorf("%q %v %v", s.Bytes(), err, f.got["get-logins"]["url"])
	}
}

// TestKeePassXCNeverSendsTheCrashingLookup: KeePassXC 2.8.0 dies
// (BrowserService.cpp:1347, std::max_element over an empty list) when
// get-logins asks for keepassxc://by-uuid/... or keepassxc://by-path/... and
// the entry found has no URL. The fake models that crash. The bytes the
// first release sent are reproduced and shown to kill it; the client now
// refuses those references before it even connects.
func TestKeePassXCNeverSendsTheCrashingLookup(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.entries["keepassxc://by-path/Yubikey PIN"] = []map[string]any{entry("pin")}
	f.crashOnURLLess = true
	withFake(t, f)

	// Before: the exact inner request of v0.2.0 for keepassxc:by-path/Yubikey PIN.
	k, err := newConn(ctx, mustDial(t, f))
	if err != nil {
		t.Fatal(err)
	}
	err = k.call("get-logins", map[string]any{"url": "keepassxc://by-path/Yubikey PIN", "keys": []map[string]string{{"id": "x", "key": "AAAA"}}}, &struct{}{})
	k.close()
	if err == nil || !f.crashed {
		t.Fatalf("the old request must kill the fake KeePassXC: %v crashed=%v", err, f.crashed)
	}

	// After: refused before any connection, whatever the spelling.
	f.crashed = false
	dialed := false
	keepassxcDial = func(context.Context) (net.Conn, error) { dialed = true; return nil, ErrUnavailable }
	for _, ref := range []string{
		"keepassxc:by-path/Yubikey PIN", "keepassxc:by-uuid/00112233445566778899aabbccddeeff",
		"keepassxc:keepassxc://by-path/Yubikey PIN", "keepassxc:by-uuid/", "keepassxc:by-path/",
	} {
		if _, err := Open(ctx, ref); !errors.Is(err, ErrBadRef) || !strings.Contains(err.Error(), "crash") {
			t.Errorf("%s: %v", ref, err)
		}
	}
	if dialed || f.crashed {
		t.Errorf("a refused reference reached KeePassXC: dialed=%v crashed=%v", dialed, f.crashed)
	}
}

func TestKeePassXCRefusals(t *testing.T) {
	ctx := context.Background()
	setup := func() (*fakeKPX, *memStore) {
		f := newFake()
		f.entries[urlURL] = []map[string]any{entry("pin")}
		ms := withFake(t, f)
		if _, err := Associate(ctx); err != nil {
			t.Fatal(err)
		}
		return f, ms
	}
	cases := []struct {
		name  string
		setup func(*fakeKPX, *memStore)
		want  error
		text  string
	}{
		{"association forgotten by KeePassXC", func(f *fakeKPX, _ *memStore) { delete(f.keys, "laptop") }, ErrNotAssociated, "no longer knows"},
		{"database locked", func(f *fakeKPX, _ *memStore) { f.errs["get-databasehash"] = "1" }, ErrUnavailable, "unlock the database"},
		{"timeout reported by KeePassXC", func(f *fakeKPX, _ *memStore) { f.errs["get-logins"] = "5" }, ErrUnavailable, ""},
		{"access refused in the dialog", func(f *fakeKPX, _ *memStore) { f.errs["get-logins"] = "6" }, ErrDenied, ""},
		{"no entry", func(f *fakeKPX, _ *memStore) { delete(f.entries, urlURL) }, ErrNotFound, ""},
		{"two entries", func(f *fakeKPX, _ *memStore) { f.entries[urlURL] = []map[string]any{entry("a"), entry("b")} }, ErrAmbiguous, "name one"},
		{"unknown error code", func(f *fakeKPX, _ *memStore) { f.errs["get-logins"] = "12" }, nil, "error 12"},
		{"test-associate unknown error", func(f *fakeKPX, _ *memStore) { f.errs["test-associate"] = "4" }, nil, "error 4"},
		{"database hash that is not hex", func(f *fakeKPX, _ *memStore) { f.hash = "../../etc/passwd" }, nil, "not hexadecimal"},
		{"hash call fails", func(f *fakeKPX, _ *memStore) { f.errs["get-databasehash"] = "13" }, nil, "error 13"},
		{"a different database", func(f *fakeKPX, _ *memStore) { f.hash = "ffff" }, ErrNotAssociated, "ffff"},
		{"empty password", func(f *fakeKPX, _ *memStore) { f.entries[urlURL] = []map[string]any{entry("")} }, ErrEmpty, ""},
		{"entries is not a list", func(f *fakeKPX, _ *memStore) {
			f.tamper = func(a string, _ map[string]string, in map[string]any) {
				if a == "get-logins" {
					in["entries"] = "x"
				}
			}
		}, nil, "cannot unmarshal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ms := setup()
			c.setup(f, ms)
			s, err := Open(ctx, refURL)
			if err == nil {
				s.Close()
				t.Fatal("a secret was returned")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("%v is not %v", err, c.want)
			}
			if !strings.Contains(err.Error(), c.text) {
				t.Errorf("%q lacks %q", err, c.text)
			}
		})
	}
}

func TestKeePassXCAssociateRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	ms := withFake(t, f)
	f.newID = ""
	if _, err := Associate(ctx); !errors.Is(err, ErrDenied) {
		t.Errorf("cancelled: %v", err)
	}
	f.newID = strings.Repeat("n", 300)
	if _, err := Associate(ctx); err == nil || !strings.Contains(err.Error(), "usable name") {
		t.Errorf("long name: %v", err)
	}
	f.newID = "ok"
	ms.saveErr = errors.New("disk full")
	if _, err := Associate(ctx); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("save: %v", err)
	}
	ms.saveErr = nil
	f.errs["get-databasehash"] = "1"
	if _, err := Associate(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("locked: %v", err)
	}
	delete(f.errs, "get-databasehash")
	keepassxcDial = func(context.Context) (net.Conn, error) { return nil, ErrUnavailable }
	if _, err := Associate(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no socket: %v", err)
	}
	keepassxcDial = f.dial
	f.tamper = func(a string, o map[string]string, _ map[string]any) {
		if a == "change-public-keys" {
			o["publicKey"] = "AAAA"
		}
	}
	if _, err := Associate(ctx); err == nil || !strings.Contains(err.Error(), "change-public-keys") {
		t.Errorf("bad server key: %v", err)
	}
}

func TestKeePassXCProtocolFaults(t *testing.T) {
	ctx := context.Background()
	faults := []struct {
		name   string
		f      func(*fakeKPX)
		text   string
		wantIs error
	}{
		{"wrong nonce on the key exchange", func(f *fakeKPX) {
			f.tamper = func(a string, o map[string]string, _ map[string]any) {
				if a == "change-public-keys" {
					o["nonce"] = b64(make([]byte, 24))
				}
			}
		}, "change-public-keys", nil},
		{"wrong nonce on a reply", func(f *fakeKPX) {
			f.tamper = func(a string, o map[string]string, _ map[string]any) {
				if a == "get-databasehash" {
					o["nonce"] = b64(make([]byte, 24))
				}
			}
		}, "nonce of the request", nil},
		{"message that is not base64", func(f *fakeKPX) {
			f.tamper = func(a string, o map[string]string, _ map[string]any) {
				if a == "get-databasehash" {
					o["message"] = "!!!"
				}
			}
		}, "not base64", nil},
		{"message that does not decrypt", func(f *fakeKPX) {
			f.tamper = func(a string, o map[string]string, _ map[string]any) {
				if a == "get-databasehash" {
					o["message"] = b64(bytes.Repeat([]byte{1}, 40))
				}
			}
		}, "does not decrypt", nil},
		{"decrypted reply that is not JSON", func(f *fakeKPX) {
			f.tamper = func(a string, o map[string]string, _ map[string]any) {
				if a == "get-databasehash" {
					o["_raw"] = "not json"
				}
			}
		}, "malformed reply", nil},
		{"success is not true", func(f *fakeKPX) {
			f.tamper = func(a string, _ map[string]string, in map[string]any) {
				if a == "get-databasehash" {
					in["success"] = "false"
				}
			}
		}, "did not succeed", nil},
		{"unsolicited notices first", func(f *fakeKPX) { f.preamble = `{"action":"database-unlocked"}{"action":"database-locked"}` }, "", nil},
		{"replies one byte at a time", func(f *fakeKPX) { f.drip = true }, "", nil},
		{"socket closed instead of an answer", func(f *fakeKPX) { f.closeOn = "get-databasehash" }, "", ErrUnavailable},
		{"socket closed at the key exchange", func(f *fakeKPX) { f.closeOn = "change-public-keys" }, "", ErrUnavailable},
		{"error reply with an unknown action is skipped forever", func(f *fakeKPX) {
			f.preamble = strings.Repeat(`{"action":"x"}`, maxSkipped+2)
		}, "no reply", nil},
	}
	for _, c := range faults {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.entries[urlURL] = []map[string]any{entry("pin")}
			withFake(t, f)
			c.f(f)
			_, err := Associate(ctx)
			if c.text == "" && c.wantIs == nil {
				if err != nil {
					t.Fatalf("a tolerated condition failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("no error")
			}
			if c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Errorf("%q lacks %q", err, c.text)
			}
			if c.wantIs != nil && !errors.Is(err, c.wantIs) {
				t.Errorf("%v is not %v", err, c.wantIs)
			}
		})
	}
}

func TestKeePassXCTimeoutWhileWaiting(t *testing.T) {
	f := newFake()
	f.silent["get-databasehash"] = true
	withFake(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Open(ctx, refURL)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "waiting for you") || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestKeePassXCNoDeadlineGetsOne(t *testing.T) {
	// Open applies Timeout; the fake answers at once so only the path is checked.
	f := newFake()
	f.entries[urlURL] = []map[string]any{entry("pin")}
	withFake(t, f)
	if _, err := Associate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(context.Background(), refURL); err != nil || string(s.Bytes()) != "pin" {
		t.Fatal(err)
	}
}

type failingReader struct{ left int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	r.left--
	return rand.Read(p)
}

func TestKeePassXCRandomSourceFailures(t *testing.T) {
	old := randReader
	t.Cleanup(func() { randReader = old })
	failed := 0
	for n := 0; n < 12; n++ {
		f := newFake()
		withFake(t, f)
		randReader = &failingReader{left: n}
		_, err := Associate(context.Background())
		if err == nil {
			break
		}
		failed++
		if !strings.Contains(err.Error(), "entropy") {
			t.Errorf("n=%d: %v", n, err)
		}
	}
	if failed < 4 {
		t.Errorf("only %d of the random reads were exercised", failed)
	}
	// call() draws its own nonce: fail only that read.
	randReader = old
	f := newFake()
	withFake(t, f)
	k, err := newConn(context.Background(), mustDial(t, f))
	if err != nil {
		t.Fatal(err)
	}
	defer k.close()
	randReader = &failingReader{}
	if err := k.call("get-databasehash", map[string]any{}, &struct{}{}); err == nil {
		t.Error("call with no entropy")
	}
}

func mustDial(t *testing.T, f *fakeKPX) net.Conn {
	t.Helper()
	c, err := f.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeePassXCWriteFails(t *testing.T) {
	c, s := net.Pipe()
	s.Close()
	k := &conn{c: c, closeFn: func() {}}
	if _, err := k.exchange("x", map[string]string{"action": "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := newConn(context.Background(), c); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("newConn on a dead socket: %v", err)
	}
}

func TestDecodeFrame(t *testing.T) {
	type row struct {
		in    string
		short bool
		bad   bool
		n     int
		act   string
	}
	for _, r := range []row{
		{in: `{"action":"a"}`, n: 14, act: "a"},
		{in: `garbage{"action":"a"}tail`, n: 21, act: "a"},
		{in: `{"action":"a"}{"action":"b"}`, n: 14, act: "a"},
		{in: ``, short: true},
		{in: `no brace yet`, short: true},
		{in: `{"action":"a`, short: true},
		{in: `{"action":"a",`, short: true},
		{in: `{"action":1}`, bad: true},
		{in: `{"action":"a"x`, bad: true},
		{in: `{]`, bad: true},
	} {
		o, n, err := decodeFrame([]byte(r.in))
		switch {
		case r.short:
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("%q: %v", r.in, err)
			}
		case r.bad:
			if err == nil || errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("%q: %v", r.in, err)
			}
		default:
			if err != nil || n != r.n || o.Action != r.act {
				t.Errorf("%q: %+v %d %v", r.in, o, n, err)
			}
		}
	}
	if _, _, err := decodeFrame(bytes.Repeat([]byte("x"), maxFrame)); err == nil || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a megabyte with no object: %v", err)
	}
}

func TestReadFrameBounds(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	go func() {
		defer s.Close()
		big := append([]byte(`{"action":"a","message":"`), bytes.Repeat([]byte("A"), maxFrame)...)
		_, _ = s.Write(big)
	}()
	k := &conn{c: c, closeFn: func() {}}
	if _, err := k.readFrame(); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Errorf("an oversize reply: %v", err)
	}
}

func TestIncrementNonce(t *testing.T) {
	var n [24]byte
	if got := incrementNonce(n); got[0] != 1 || got[1] != 0 {
		t.Errorf("%v", got)
	}
	n[0], n[1] = 255, 255
	if got := incrementNonce(n); got[0] != 0 || got[1] != 0 || got[2] != 1 {
		t.Errorf("carry: %v", got)
	}
	for i := range n {
		n[i] = 255
	}
	if got := incrementNonce(n); got != [24]byte{} {
		t.Errorf("wrap: %v", got)
	}
}

func TestKpxErrorMapping(t *testing.T) {
	for code, target := range map[int]error{1: ErrUnavailable, 5: ErrUnavailable, 6: ErrDenied, 8: ErrNotAssociated, 15: ErrNotFound} {
		e := &kpxError{Code: code, Text: "t"}
		if !errors.Is(e, target) || errors.Is(e, ErrEmpty) || !strings.Contains(e.Error(), "t") {
			t.Errorf("code %d", code)
		}
	}
	if errors.Is(&kpxError{Code: 99}, ErrNotFound) {
		t.Error("99 is not not-found")
	}
}

func TestParseKeePassXC(t *testing.T) {
	ok := map[string]string{
		"keepassxc:theca://vault":               "keepassxc:theca://vault",
		"keepassxc:https://theca.invalid/vault": "keepassxc:https://theca.invalid/vault",
	}
	for in, back := range ok {
		r, err := Parse(in)
		if err != nil || r.String() != back || r.Scheme != "keepassxc" || r.entryURL() != r.Entry {
			t.Errorf("%q: %+v %v", in, r, err)
		}
	}
	for _, in := range []string{
		"keepassxc:", "keepassxc:Entry", "keepassxc:by-uuid/xyz", "keepassxc:by-uuid/", "keepassxc:by-path/",
		"keepassxc:by-path/Keys/Yubikey PIN", "keepassxc:by-uuid/00112233445566778899aabbccddeeff",
		"keepassxc:keepassxc://by-uuid/00112233445566778899aabbccddeeff", "keepassxc:" + strings.Repeat("a", 1100) + "://",
	} {
		if _, err := Parse(in); !errors.Is(err, ErrBadRef) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestSocketCandidates(t *testing.T) {
	save := []any{goos, userTempDir, getenv, currentUserName}
	t.Cleanup(func() {
		goos, userTempDir, getenv, currentUserName = save[0].(string), save[1].(func() string), save[2].(func(string) string), save[3].(func() string)
	})
	userTempDir = func() string { return "/var/folders/x/T" }
	currentUserName = func() string { return "bob" }
	getenv = func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return "/run/user/1000"
		}
		return ""
	}
	goos = "darwin"
	if c, err := socketCandidates(); err != nil || len(c) != 1 || c[0] != "/var/folders/x/T/org.keepassxc.KeePassXC.BrowserServer" {
		t.Errorf("darwin: %v %v", c, err)
	}
	goos = "linux"
	c, err := socketCandidates()
	if err != nil || len(c) != 2 || c[0] != "/run/user/1000/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer" || c[1] != "/run/user/1000/org.keepassxc.KeePassXC.BrowserServer" {
		t.Errorf("linux: %v %v", c, err)
	}
	getenv = func(string) string { return "" }
	if c, _ := socketCandidates(); !strings.HasPrefix(c[0], "/var/folders/x/T/runtime-bob/app/") {
		t.Errorf("no XDG_RUNTIME_DIR: %v", c)
	}
	goos = "windows"
	if _, err := socketCandidates(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("windows: %v", err)
	}
	if _, err := dialKeePassXC(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("dial on windows: %v", err)
	}
}

func TestDialKeePassXC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets")
	}
	dir, err := os.MkdirTemp("", "kpx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	save := []any{goos, getenv}
	t.Cleanup(func() { goos, getenv = save[0].(string), save[1].(func(string) string) })
	goos = "linux"
	getenv = func(string) string { return dir }
	ctx := context.Background()

	if _, err := dialKeePassXC(ctx); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "Browser Integration") {
		t.Fatalf("no socket: %v", err)
	}
	// A regular file where the socket should be is refused, not written to.
	if err := os.WriteFile(filepath.Join(dir, sockName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dialKeePassXC(ctx); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("a file: %v", err)
	}
	os.Remove(filepath.Join(dir, sockName))
	// A socket, reached at the legacy path.
	l, err := net.Listen("unix", filepath.Join(dir, sockName))
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := dialKeePassXC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	checkOwner(t, filepath.Join(dir, sockName))
	// A socket file that nobody listens on.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := dialKeePassXC(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dead socket: %v", err)
	}
}

func TestAssocStores(t *testing.T) {
	// kvStore over fakes of the keychain and the Secret Service.
	mem := map[string][]byte{}
	kv := kvStore{
		get: func(s, a string) ([]byte, error) {
			if b, ok := mem[s+"/"+a]; ok {
				return b, nil
			}
			return nil, keychain.ErrNotFound
		},
		set: func(s, a string, b []byte) error { mem[s+"/"+a] = b; return nil }, where: "the fake",
	}
	if _, err := kv.load("ab"); !errors.Is(err, ErrNotAssociated) {
		t.Fatal(err)
	}
	if err := kv.save("ab", assoc{ID: "i", Key: "k"}); err != nil {
		t.Fatal(err)
	}
	if a, err := kv.load("ab"); err != nil || a.ID != "i" {
		t.Fatal(a, err)
	}
	kv.get = func(string, string) ([]byte, error) { return nil, secretservice.ErrNotFound }
	if _, err := kv.load("ab"); !errors.Is(err, ErrNotAssociated) {
		t.Fatal(err)
	}
	kv.get = func(string, string) ([]byte, error) { return nil, errors.New("locked") }
	if _, err := kv.load("ab"); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "the fake") {
		t.Fatal(err)
	}
	kv.get = func(string, string) ([]byte, error) { return []byte("{"), nil }
	if _, err := kv.load("ab"); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatal(err)
	}
	kv.set = func(string, string, []byte) error { return errors.New("refused") }
	if err := kv.save("ab", assoc{}); err == nil || !strings.Contains(err.Error(), "the fake") {
		t.Fatal(err)
	}

	// fileStore under a configuration directory of our own.
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		old := userConfigDir
		userConfigDir = func() (string, error) { return dir, nil }
		t.Cleanup(func() { userConfigDir = old })
		var fs fileStore
		if _, err := fs.load("ab"); !errors.Is(err, ErrNotAssociated) {
			t.Fatal(err)
		}
		if err := fs.save("ab", assoc{ID: "i", Key: "k"}); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "secretsource", "keepassxc-ab.json")
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%v %v", st, err)
		}
		if a, err := fs.load("ab"); err != nil || a.Key != "k" {
			t.Fatal(a, err)
		}
		os.Chmod(p, 0o644)
		if _, err := fs.load("ab"); err == nil || !strings.Contains(err.Error(), "mode 0644") {
			t.Fatalf("a world-readable association file: %v", err)
		}
		os.WriteFile(p, []byte("{}"), 0o600)
		os.Chmod(p, 0o600)
		if _, err := fs.load("ab"); err == nil || !strings.Contains(err.Error(), "damaged") {
			t.Fatal(err)
		}
		// A configuration directory that is a file.
		blocker := filepath.Join(dir, "blocker")
		os.WriteFile(blocker, nil, 0o600)
		userConfigDir = func() (string, error) { return blocker, nil }
		if err := fs.save("ab", assoc{}); err == nil {
			t.Error("save under a file")
		}
		userConfigDir = func() (string, error) { return "", errors.New("no home") }
		if _, err := fs.load("ab"); err == nil {
			t.Error("load with no config dir")
		}
		if err := fs.save("ab", assoc{}); err == nil {
			t.Error("save with no config dir")
		}
	}

	// The default choice per platform.
	save := []any{goos, ssAvailable}
	t.Cleanup(func() { goos, ssAvailable = save[0].(string), save[1].(func() bool) })
	ssAvailable = func() bool { return true }
	goos = "darwin"
	if s := defaultAssocStore().(kvStore); s.where != "the macOS Keychain" {
		t.Error(s.where)
	}
	goos = "linux"
	if s := defaultAssocStore().(kvStore); s.where != "the Secret Service" {
		t.Error(s.where)
	}
	ssAvailable = func() bool { return false }
	if _, ok := defaultAssocStore().(fileStore); !ok {
		t.Error("no Secret Service: a file")
	}
	goos = "windows"
	if _, ok := defaultAssocStore().(fileStore); !ok {
		t.Error("windows: a file")
	}
}

func TestKeychainSetWrapper(t *testing.T) {
	// The real wrapper reaches keychain.Set; off darwin that is ErrUnsupported
	// (on darwin an empty secret is refused before the Keychain is touched).
	if err := keychainSet("secretsource-test", "x", nil); err == nil {
		t.Fatal("an empty secret was stored")
	}
}

func FuzzDecodeFrame(f *testing.F) {
	for _, s := range []string{
		`{"action":"get-logins","message":"AAAA","nonce":"BBBB"}`,
		`{"action":"change-public-keys","publicKey":"x","nonce":"y","version":"2.7.9","success":"true"}`,
		`{"action":"a","errorCode":"15","error":"no"}{"action":"database-locked"}`,
		`garbage{"action":"a"`, ``, `{`, `{"action":1}`, `[]`, `null`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		o, n, err := decodeFrame(b)
		if err != nil {
			return
		}
		if n <= 0 || n > len(b) {
			t.Fatalf("consumed %d of %d", n, len(b))
		}
		_ = o
		// What was consumed is a complete object by itself.
		if _, m, err := decodeFrame(b[:n]); err != nil || m != n {
			t.Fatalf("re-decoding the consumed prefix: %d %v", m, err)
		}
	})
}
