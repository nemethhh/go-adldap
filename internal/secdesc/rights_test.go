package secdesc_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/secdesc"
)

func TestRightsMask(t *testing.T) {
	cases := []struct {
		name string
		in   []adcore.Right
		want uint32
	}{
		{"generic all", []adcore.Right{"GenericAll"}, 0x000F01FF},
		{"read property", []adcore.Right{"ReadProperty"}, 0x00000010},
		{"write property", []adcore.Right{"WriteProperty"}, 0x00000020},
		{"extended right", []adcore.Right{"ExtendedRight"}, 0x00000100},
		{"delete pair", []adcore.Right{"Delete", "DeleteTree"}, 0x00010000 | 0x00000040},
		{"create and delete child", []adcore.Right{"CreateChild", "DeleteChild"}, 0x00000001 | 0x00000002},
		{"combined", []adcore.Right{"ReadProperty", "WriteProperty"}, 0x00000030},
		// Case is not significant: the provider accepts what a user typed and
		// AD's own tooling is case-insensitive here.
		{"case insensitive", []adcore.Right{"readproperty"}, 0x00000010},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := secdesc.RightsMask(tc.in)
			if err != nil {
				t.Fatalf("RightsMask(%v): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("RightsMask(%v) = %#x, want %#x", tc.in, got, tc.want)
			}
		})
	}
}

// An unknown right is an error naming it. Silently dropping it would grant
// less than the user asked for and report success — the worst outcome
// available in an access-control system.
func TestRightsMaskRejectsAnUnknownName(t *testing.T) {
	_, err := secdesc.RightsMask([]adcore.Right{"ReadProperty", "SuperUser"})
	if err == nil {
		t.Fatal("want an error for an unknown right, got nil")
	}
	if !strings.Contains(err.Error(), "SuperUser") {
		t.Errorf("error %q does not name the offending right", err)
	}
}

func TestRightsNames(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want []adcore.Right
	}{
		// GenericAll is emitted as the single name whenever every bit it
		// covers is set, because that is what AD's tooling shows and what the
		// PowerShell backend emits. Listing its nine constituent rights
		// instead would be a permanent diff for anyone switching backends.
		{"generic all", 0x000F01FF, []adcore.Right{"GenericAll"}},
		{"read property", 0x00000010, []adcore.Right{"ReadProperty"}},
		{"combined, in bit order", 0x00000030, []adcore.Right{"ReadProperty", "WriteProperty"}},
		{"none", 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := secdesc.RightsNames(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RightsNames(%#x) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRightsRoundTrip(t *testing.T) {
	for _, in := range [][]adcore.Right{
		{"GenericAll"},
		{"ReadProperty", "WriteProperty"},
		{"ExtendedRight"},
		{"CreateChild", "DeleteChild", "ListChildren"},
	} {
		mask, err := secdesc.RightsMask(in)
		if err != nil {
			t.Fatalf("RightsMask(%v): %v", in, err)
		}
		back, err := secdesc.RightsMask(secdesc.RightsNames(mask))
		if err != nil {
			t.Fatalf("RightsMask(RightsNames(%#x)): %v", mask, err)
		}
		if back != mask {
			t.Errorf("%v: mask %#x did not survive a round trip, got %#x", in, mask, back)
		}
	}
}
