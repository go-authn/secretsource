package secretsource

import (
	"strings"
	"testing"
)

const (
	sidOwner    = "S-1-5-21-1-2-3-1001"
	sidOther    = "S-1-5-21-1-2-3-1002"
	sidEveryone = "S-1-1-0"

	fileAll   = 0x1F01FF
	fileRead  = 0x120089 // FILE_GENERIC_READ
	fileWrite = 0x100116 // FILE_GENERIC_WRITE less READ_CONTROL
)

func TestDaclVerdict(t *testing.T) {
	for _, c := range []struct {
		name string
		aces []ace
		// want is a fragment of the refusal, "" for acceptance.
		want string
	}{
		{"empty list: nobody has access", nil, ""},
		{"owner, SYSTEM, Administrators", []ace{
			{aceAllowed, 0, fileAll, sidOwner},
			{aceAllowed, 0, fileAll, sidSystem},
			{aceAllowed, 0, fileAll, sidAdministrators},
		}, ""},
		{"Everyone reads", []ace{{aceAllowed, 0, fileRead, sidEveryone}}, "S-1-1-0"},
		{"another user writes", []ace{{aceAllowed, 0, fileWrite, sidOther}}, "S-1-5-21-1-2-3-1002"},
		{"another user may only read attributes and the list", []ace{{aceAllowed, 0, 0x80 | 0x20000 | 0x100000, sidOther}}, ""},
		{"callback allow counts as a grant", []ace{{aceAllowedCB, 0, fileRead, sidEveryone}}, "S-1-1-0"},
		{"a deny is ignored: it grants nothing", []ace{
			{aceDenied, 0, fileAll, sidEveryone},
			{aceDeniedCB, 0, fileAll, sidOther},
			{aceDeniedObject, 0, fileAll, ""},
			{aceDeniedCBObject, 0, fileAll, ""},
		}, ""},
		{"a deny does not excuse a later allow", []ace{
			{aceDenied, 0, fileAll, sidEveryone},
			{aceAllowed, 0, fileRead, sidEveryone},
		}, "S-1-1-0"},
		{"an allow before a deny still grants", []ace{
			{aceAllowed, 0, fileRead, sidEveryone},
			{aceDenied, 0, fileAll, sidEveryone},
		}, "S-1-1-0"},
		{"inherit-only does not apply to this file", []ace{{aceAllowed, aceInheritOnly, fileAll, sidEveryone}}, ""},
		{"an inherited entry applies (flag 0x10 is not inherit-only)", []ace{{aceAllowed, 0x10, fileRead, sidEveryone}}, "S-1-1-0"},
		{"an object entry cannot be checked", []ace{{0x05, 0, fileAll, ""}}, "type 0x5"},
		{"an unknown entry cannot be checked", []ace{{0x7f, 0, 0, ""}}, "type 0x7f"},
		{"an inert unknown entry, inherit-only, is skipped", []ace{{0x7f, aceInheritOnly, 0, ""}}, ""},
	} {
		err := daclVerdict(sidOwner, c.aces)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want a refusal containing %q", c.name, err, c.want)
		}
	}
	for _, bit := range []uint32{0x1, 0x2, 0x4, 0x10, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x80000000} {
		if err := daclVerdict(sidOwner, []ace{{aceAllowed, 0, bit, sidOther}}); err == nil {
			t.Errorf("right %#x granted to another user was accepted", bit)
		}
		if err := daclVerdict(sidOwner, []ace{{aceAllowed, 0, bit, sidOwner}}); err != nil {
			t.Errorf("right %#x granted to the owner: %v", bit, err)
		}
	}
	// The rights that reveal nothing are exactly the complement.
	for _, bit := range []uint32{0x8, 0x20, 0x40, 0x80, 0x100, 0x20000, 0x100000, 0x1000000, 0x2000000, 0x20000000} {
		if err := daclVerdict(sidOwner, []ace{{aceAllowed, 0, bit, sidOther}}); err != nil {
			t.Errorf("harmless right %#x refused: %v", bit, err)
		}
	}
}

func TestHasSID(t *testing.T) {
	for typ := 0; typ < 256; typ++ {
		want := typ == 0 || typ == 1 || typ == 9 || typ == 10
		if hasSID(byte(typ)) != want {
			t.Errorf("hasSID(%#x) = %v", typ, !want)
		}
	}
}
