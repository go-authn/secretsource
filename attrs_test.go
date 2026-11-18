package secretsource

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-freedesktop/secretservice"
)

func TestParseAttrs(t *testing.T) {
	ok := map[string]string{
		"secretservice:Title=Yubikey PIN":          "secretservice:Title=Yubikey PIN",
		"secretservice:UserName=me,Title=PIN":      "secretservice:Title=PIN,UserName=me",
		"secretservice:Title=PIN,UserName=me":      "secretservice:Title=PIN,UserName=me",
		"secretservice:URL=https://a/b?c=d":        "secretservice:URL=https://a/b?c=d",
		"secretservice:service=fido,account=a/b=c": "secretservice:account=a/b=c,service=fido",
	}
	for in, back := range ok {
		r, err := Parse(in)
		if err != nil || r.String() != back || r.Attrs == "" {
			t.Errorf("%q: %+v %v", in, r, err)
		}
	}
	r, _ := Parse("secretservice:b=2,a=1")
	if m := r.AttrMap(); len(m) != 2 || m["a"] != "1" || m["b"] != "2" {
		t.Errorf("%v", m)
	}
	bad := []string{
		"secretservice:=x", "secretservice:a=", "secretservice:a=1,a=2", "secretservice:a=1,", "secretservice:a=1,,b=2",
		"secretservice:" + strings.Repeat("k=v,", 32) + "z=1",
	}
	for _, in := range bad {
		if _, err := Parse(in); !errors.Is(err, ErrBadRef) {
			t.Errorf("%q: %v", in, err)
		}
	}
	// 32 distinct pairs is the bound.
	var pairs []string
	for i := 0; i < 33; i++ {
		pairs = append(pairs, string(rune('a'+i%26))+string(rune('A'+i/26))+"=v")
	}
	if _, err := Parse("secretservice:" + strings.Join(pairs[:32], ",")); err != nil {
		t.Errorf("32 pairs: %v", err)
	}
	if _, err := Parse("secretservice:" + strings.Join(pairs, ",")); !errors.Is(err, ErrBadRef) {
		t.Errorf("33 pairs: %v", err)
	}
	// keychain does not take attributes: the "=" stays part of the account.
	if r, err := Parse("keychain:svc/a=b"); err != nil || r.Account != "a=b" {
		t.Errorf("%+v %v", r, err)
	}
}

func TestSecretServiceByAttributes(t *testing.T) {
	var got map[string]string
	old := secretserviceGetAttrs
	t.Cleanup(func() { secretserviceGetAttrs = old })
	secretserviceGetAttrs = func(m map[string]string) ([]byte, error) { got = m; return []byte("246810"), nil }
	s, err := Open(context.Background(), "secretservice:Title=Yubikey PIN,UserName=me")
	if err != nil || string(s.Bytes()) != "246810" || got["Title"] != "Yubikey PIN" || got["UserName"] != "me" {
		t.Fatalf("%q %v %v", s.Bytes(), err, got)
	}
	secretserviceGetAttrs = func(map[string]string) ([]byte, error) { return nil, secretservice.ErrNotFound }
	if _, err := Open(context.Background(), "secretservice:Title=x"); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "Title=x") {
		t.Errorf("not found: %v", err)
	}
	secretserviceGetAttrs = func(map[string]string) ([]byte, error) { return nil, secretservice.ErrAmbiguous }
	if _, err := Open(context.Background(), "secretservice:Title=x"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("ambiguous: %v", err)
	}
}
