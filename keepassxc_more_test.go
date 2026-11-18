package secretsource

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestKeePassXCOpenEdges(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.entries[urlUUID] = []map[string]any{entry("pin")}
	withFake(t, f)
	if _, err := Associate(ctx); err != nil {
		t.Fatal(err)
	}
	// Success with an empty list is still "no entry".
	f.tamper = func(a string, _ map[string]string, in map[string]any) {
		if a == "get-logins" {
			in["entries"] = []any{}
		}
	}
	if _, err := Open(ctx, refUUID); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty list: %v", err)
	}
	f.tamper = nil
	// No socket at all.
	keepassxcDial = func(context.Context) (net.Conn, error) { return nil, ErrUnavailable }
	if _, err := Open(ctx, refUUID); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no socket: %v", err)
	}
	// A socket that closes at once.
	keepassxcDial = func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		s.Close()
		return c, nil
	}
	if _, err := Open(ctx, refUUID); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "waiting for you") {
		t.Errorf("closed socket: %v", err)
	}
	// A reply that is not the object the protocol allows.
	keepassxcDial = f.dial
	f.preamble = `{"action":1}`
	if _, err := Open(ctx, refUUID); err == nil || !strings.Contains(err.Error(), "malformed reply") {
		t.Errorf("non-string field: %v", err)
	}
}

func TestDefaultUserName(t *testing.T) {
	t.Setenv("USER", "carol")
	if currentUserName() != "carol" {
		t.Fatal(currentUserName())
	}
}
