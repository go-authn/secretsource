package secretsource

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSystemdCreds(t *testing.T) {
	r, err := Parse("systemd-creds:smtp.password")
	if err != nil || r.Scheme != "systemd-creds" || r.Name != "smtp.password" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{
		"systemd-creds:", "systemd-creds:..", "systemd-creds:.", "systemd-creds:a/b", "systemd-creds:/etc/shadow",
		"systemd-creds:a\x00b", "systemd-creds:a\nb", "systemd-creds:" + strings.Repeat("a", 256),
	} {
		if _, err := Parse(bad); !errors.Is(err, ErrBadRef) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := Parse("systemd-creds:" + strings.Repeat("a", 255)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCredNameMessages(t *testing.T) {
	for name, want := range map[string]string{
		"": "empty", "..": "directory", "a/b": "slash", "a\tb": "control", strings.Repeat("x", 300): "longer",
	} {
		if err := checkCredName(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func FuzzCredName(f *testing.F) {
	for _, s := range []string{"theca", "a.b-c_d", "..", ".", "", "a/b", "a\x00", "../x", "é", strings.Repeat("a", 256)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := checkCredName(name)
		if err == nil {
			// Anything accepted is a plain, bounded file name.
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || len(name) > maxCredName {
				t.Fatalf("accepted %q", name)
			}
		}
		_, perr := Parse("systemd-creds:" + name)
		if (err == nil) != (perr == nil) {
			t.Fatalf("Parse and checkCredName disagree on %q: %v vs %v", name, err, perr)
		}
	})
}
