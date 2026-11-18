package secretsource

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-freedesktop/secretservice"
	"github.com/go-macos/keychain"
)

func fakeKeychain(t *testing.T, fn func(service, account string) ([]byte, error)) {
	t.Helper()
	old := keychainGet
	keychainGet = fn
	t.Cleanup(func() { keychainGet = old })
}

func fakeSecretService(t *testing.T, fn func(service, account string) ([]byte, error)) {
	t.Helper()
	old := secretserviceGet
	secretserviceGet = fn
	t.Cleanup(func() { secretserviceGet = old })
}

func TestParse(t *testing.T) {
	ok := []struct {
		in   string
		want Ref
		back string
	}{
		{"file:/run/pin", Ref{Scheme: "file", Path: "/run/pin"}, "file:/run/pin"},
		{"file:C:\\k\\pin", Ref{Scheme: "file", Path: "C:\\k\\pin"}, "file:C:\\k\\pin"},
		{"keychain:fido/yubikey", Ref{Scheme: "keychain", Service: "fido", Account: "yubikey"}, "keychain:fido/yubikey"},
		{"keychain:fido/a/b", Ref{Scheme: "keychain", Service: "fido", Account: "a/b"}, "keychain:fido/a/b"},
		{"secretservice:theca/me@x.org", Ref{Scheme: "secretservice", Service: "theca", Account: "me@x.org"}, "secretservice:theca/me@x.org"},
	}
	for _, c := range ok {
		got, err := Parse(c.in)
		if err != nil || got != c.want || got.String() != c.back {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	bad := []struct {
		in  string
		err error
	}{
		{"", ErrBadRef},
		{"/etc/pin", ErrBadRef}, // a bare path is not guessed
		{"file:", ErrBadRef},
		{"keychain:", ErrBadRef},
		{"keychain:svc", ErrBadRef},
		{"keychain:/acct", ErrBadRef},
		{"keychain:svc/", ErrBadRef},
		{"secretservice:svc", ErrBadRef},
		{"file:a\x00b", ErrBadRef},
		{"keychain:a\n/b", ErrBadRef},
		{"cmd:cat /etc/passwd", ErrScheme}, // no exec scheme, ever
		{"exec:true", ErrScheme},
		{"env:PIN", ErrScheme},
		{"FILE:/x", ErrScheme}, // schemes are lowercase
		{"keepassxc:Entry", ErrScheme},
		{"C:\\pin", ErrScheme},
		{"http://x/y", ErrScheme},
	}
	for _, c := range bad {
		if _, err := Parse(c.in); !errors.Is(err, c.err) {
			t.Errorf("Parse(%q) = %v; want %v", c.in, err, c.err)
		}
	}
}

func TestClipLongReference(t *testing.T) {
	_, err := Parse(strings.Repeat("x", 500))
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), "...") {
		t.Fatalf("a long malformed reference is quoted whole: %v", err)
	}
}

func writeSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	for _, c := range []struct{ content, want string }{
		{"1234\n", "1234"},
		{"1234\r\n", "1234"},
		{"1234", "1234"},
		{"12\n34\n", "12\n34"},
		{"\n", ""},
		{"", ""},
		{"\r\n", ""},
	} {
		s, err := Open(context.Background(), "file:"+writeSecret(t, c.content, 0o600))
		if err != nil || string(s.Bytes()) != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.content, s.Bytes(), err, c.want)
		}
		s.Close()
	}
	// Stricter than 0600 is fine.
	if _, err := Open(context.Background(), "file:"+writeSecret(t, "x", 0o400)); err != nil {
		t.Errorf("0400: %v", err)
	}
}

func TestOpenFileRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	ctx := context.Background()
	if _, err := Open(ctx, "file:"+writeSecret(t, "x", 0o640)); err == nil || !strings.Contains(err.Error(), "mode 0640") {
		t.Errorf("0640 must be refused: %v", err)
	}
	if _, err := Open(ctx, "file:"+writeSecret(t, "x", 0o604)); err == nil {
		t.Error("0604 must be refused")
	}
	if _, err := Open(ctx, "file:"+t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	if _, err := Open(ctx, "file:"+filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := Open(ctx, "file:"+writeSecret(t, strings.Repeat("a", MaxSize+1), 0o600)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	if _, err := Open(ctx, "file:"+writeSecret(t, strings.Repeat("a", MaxSize), 0o600)); err != nil {
		t.Errorf("exactly the bound: %v", err)
	}
}

func TestOpenBadRef(t *testing.T) {
	if _, err := Open(context.Background(), "nope"); !errors.Is(err, ErrBadRef) {
		t.Fatal(err)
	}
}

func TestOpenCanceledContext(t *testing.T) {
	called := false
	fakeKeychain(t, func(string, string) ([]byte, error) { called = true; return []byte("x"), nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, "keychain:a/b"); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("a dead context must not reach the manager: %v called=%v", err, called)
	}
}

// managers runs the shared scenarios against both manager schemes.
func TestManagers(t *testing.T) {
	type mgr struct {
		scheme                       string
		fake                         func(*testing.T, func(string, string) ([]byte, error))
		notFound, unavailable, other error
	}
	for _, m := range []mgr{
		{"keychain", fakeKeychain, keychain.ErrNotFound, keychain.ErrUnsupported, &keychain.Error{Op: "get", Status: -1}},
		{"secretservice", fakeSecretService, secretservice.ErrNotFound, secretservice.ErrUnavailable, errors.New("unlock: boom")},
	} {
		t.Run(m.scheme, func(t *testing.T) {
			ref := m.scheme + ":fido/key"
			ctx := context.Background()

			var gotS, gotA string
			m.fake(t, func(s, a string) ([]byte, error) { gotS, gotA = s, a; return []byte("123456"), nil })
			s, err := Open(ctx, ref)
			if err != nil || string(s.Bytes()) != "123456" || gotS != "fido" || gotA != "key" {
				t.Fatalf("got %q, %v (%q/%q)", s.Bytes(), err, gotS, gotA)
			}
			b := s.Bytes()
			s.Close()
			if !bytes.Equal(b, make([]byte, 6)) {
				t.Errorf("Close did not wipe: %q", b)
			}
			s.Close() // twice is fine

			// No newline stripping outside files: the manager's bytes are the secret.
			m.fake(t, func(string, string) ([]byte, error) { return []byte("pw\n"), nil })
			if s, _ := Open(ctx, ref); string(s.Bytes()) != "pw\n" {
				t.Errorf("manager bytes altered: %q", s.Bytes())
			}

			m.fake(t, func(string, string) ([]byte, error) { return nil, m.notFound })
			if _, err := Open(ctx, ref); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "fido") {
				t.Errorf("missing entry: %v", err)
			}
			m.fake(t, func(string, string) ([]byte, error) { return nil, m.unavailable })
			if _, err := Open(ctx, ref); !errors.Is(err, ErrUnavailable) {
				t.Errorf("unavailable: %v", err)
			}
			m.fake(t, func(string, string) ([]byte, error) { return nil, m.other })
			if _, err := Open(ctx, ref); err == nil || !strings.Contains(err.Error(), ref) {
				t.Errorf("other: %v", err)
			}
			m.fake(t, func(string, string) ([]byte, error) { return nil, nil })
			if _, err := Open(ctx, ref); !errors.Is(err, ErrEmpty) {
				t.Errorf("empty: %v", err)
			}
			big := bytes.Repeat([]byte("a"), MaxSize+1)
			m.fake(t, func(string, string) ([]byte, error) { return big, nil })
			if _, err := Open(ctx, ref); !errors.Is(err, ErrTooLarge) || big[0] != 0 {
				t.Errorf("too large (and wiped): %v", err)
			}

			// A manager that never answers (a locked one waiting for the person)
			// ends with the context, and its late answer is wiped.
			release := make(chan struct{})
			late := []byte("late-secret")
			done := make(chan struct{})
			m.fake(t, func(string, string) ([]byte, error) {
				<-release
				defer close(done)
				return late, nil
			})
			tctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err = Open(tctx, ref)
			if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "locked") || time.Since(start) > 2*time.Second {
				t.Errorf("timeout: %v after %v", err, time.Since(start))
			}
			close(release)
			<-done
			deadline := time.Now().Add(2 * time.Second)
			for !bytes.Equal(late, make([]byte, len(late))) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if !bytes.Equal(late, make([]byte, len(late))) {
				t.Errorf("a late answer was not wiped: %q", late)
			}
		})
	}
}

func TestKeychainLockedStatuses(t *testing.T) {
	for _, st := range []int32{-25308, -25293, -128} {
		fakeKeychain(t, func(string, string) ([]byte, error) { return nil, &keychain.Error{Op: "get", Status: st} })
		if _, err := Open(context.Background(), "keychain:a/b"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("status %d: %v", st, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"file:/x", "keychain:a/b", "secretservice:a/b", "", ":", "keychain:/", "cmd:x", "file:\x00", "a:b:c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r, err := Parse(in)
		if err != nil {
			if !errors.Is(err, ErrBadRef) && !errors.Is(err, ErrScheme) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		switch r.Scheme {
		case "file", "keychain", "secretservice":
		default:
			t.Fatalf("scheme %q must not parse", r.Scheme)
		}
		// A parsed reference renders to one that parses back to itself.
		back, err := Parse(r.String())
		if err != nil || back != r {
			t.Fatalf("%q -> %+v -> %q -> %+v, %v", in, r, r.String(), back, err)
		}
	})
}
