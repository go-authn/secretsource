//go:build windows

package secretsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func sddl(t *testing.T, s string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return sd
}

func TestParseSD(t *testing.T) {
	owner, aces, err := parseSD(sddl(t, "O:BAD:P(A;;FA;;;SY)(D;;FR;;;WD)(A;OICIIO;FR;;;WD)(A;;FR;;;BA)"))
	if err != nil || owner != sidAdministrators || len(aces) != 4 {
		t.Fatalf("got %q %v %v", owner, aces, err)
	}
	want := []ace{
		{aceAllowed, 0, 0x1F01FF, sidSystem},
		{aceDenied, 0, 0x120089, sidEveryone},
		{aceAllowed, 0x08 | 0x01 | 0x02, 0x120089, sidEveryone},
		{aceAllowed, 0, 0x120089, sidAdministrators},
	}
	for i := range want {
		if aces[i] != want[i] {
			t.Errorf("ace %d: got %+v, want %+v", i, aces[i], want[i])
		}
	}
	// An object entry is read without its SID, which is not at the plain offset.
	_, aces, err = parseSD(sddl(t, "O:BAD:(OA;;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)"))
	if err != nil || len(aces) != 1 || aces[0].Type != 0x05 || aces[0].SID != "" {
		t.Errorf("object entry: %+v %v", aces, err)
	}
	// An empty, protected list is not a refusal.
	if _, aces, err = parseSD(sddl(t, "O:BAD:P")); err != nil || len(aces) != 0 {
		t.Errorf("empty list: %v %v", aces, err)
	}
}

func TestParseSDRefusals(t *testing.T) {
	for _, c := range []struct{ name, s, want string }{
		{"no owner", "D:P(A;;FA;;;SY)", "no owner"},
		{"null DACL", "O:BAD:NO_ACCESS_CONTROL", "no access list"},
		{"no DACL", "O:BA", "no access list"},
	} {
		if _, _, err := parseSD(sddl(t, c.s)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	old := getAce
	defer func() { getAce = old }()
	boom := errors.New("boom")
	getAce = func(*windows.ACL, uint32, **windows.ACCESS_ALLOWED_ACE) error { return boom }
	if _, _, err := parseSD(sddl(t, "O:BAD:(A;;FA;;;SY)")); !errors.Is(err, boom) {
		t.Errorf("GetAce failure: %v", err)
	}
}

// protect gives path exactly the entries of list, no inheritance, and makes
// owner the owner's SID in them where the list says %s.
func protect(t *testing.T, path, entries string) {
	t.Helper()
	owner := ownerSID(t, path)
	sd := sddl(t, "D:P"+strings.ReplaceAll(entries, "%s", owner))
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func ownerSID(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o.String()
}

func newSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenFileWindows(t *testing.T) {
	ctx := context.Background()

	p := newSecret(t, "1234\r\n")
	protect(t, p, "(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)")
	s, err := Open(ctx, "file:"+p)
	if err != nil || string(s.Bytes()) != "1234" {
		t.Fatalf("a private file: %q, %v", s.Bytes(), err)
	}
	s.Close()

	for name, entries := range map[string]string{
		"Everyone reads":       "(A;;FA;;;%s)(A;;FR;;;WD)",
		"Authenticated reads":  "(A;;FA;;;%s)(A;;FR;;;AU)",
		"Users read":           "(A;;FA;;;%s)(A;;FR;;;BU)",
		"Everyone writes":      "(A;;FA;;;%s)(A;;FW;;;WD)",
		"deny does not excuse": "(D;;FA;;;WD)(A;;FA;;;%s)(A;;FR;;;WD)",
	} {
		p := newSecret(t, "1234")
		protect(t, p, entries)
		if _, err := Open(ctx, "file:"+p); err == nil || strings.Contains(err.Error(), "mode") {
			t.Errorf("%s: got %v, want a refusal that names no mode", name, err)
		}
	}

	// An empty, protected list: nobody but the owner could read, and the
	// open fails before any verdict is reached or the verdict accepts.
	p = newSecret(t, "x")
	protect(t, p, "")
	if s, err := Open(ctx, "file:"+p); err == nil {
		s.Close()
	} else if !errors.Is(err, os.ErrPermission) {
		t.Errorf("empty list: %v", err)
	}
}

func TestCheckSecretFileReadFailure(t *testing.T) {
	old := readSD
	defer func() { readSD = old }()
	boom := errors.New("boom")
	readSD = func(windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) { return nil, boom }
	f, err := os.Open(newSecret(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkSecretFile(f, nil, "p"); !errors.Is(err, boom) {
		t.Errorf("got %v", err)
	}
	readSD = func(windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) { return sddl(t, "D:P(A;;FA;;;SY)"), nil }
	if err := checkSecretFile(f, nil, "p"); err == nil || !strings.Contains(err.Error(), "no owner") {
		t.Errorf("a descriptor without an owner: %v", err)
	}
}
