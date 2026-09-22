package secdesc

import (
	"bytes"
	"testing"
)

// domainSID is S-1-5-21-1-2-3, the shape every real domain SID has.
var domainSID = []byte{
	1, 4, 0, 0, 0, 0, 0, 5, // revision 1, 4 sub-authorities, authority 5
	21, 0, 0, 0,
	1, 0, 0, 0,
	2, 0, 0, 0,
	3, 0, 0, 0,
}

func sidWithRID(domain []byte, rid uint32) []byte {
	out := make([]byte, len(domain)+4)
	copy(out, domain)
	out[1]++ // one more sub-authority
	out[len(domain)] = byte(rid)
	out[len(domain)+1] = byte(rid >> 8)
	out[len(domain)+2] = byte(rid >> 16)
	out[len(domain)+3] = byte(rid >> 24)
	return out
}

func TestBuildPrincipalSDRoundTrips(t *testing.T) {
	a := sidWithRID(domainSID, 1104)
	b := sidWithRID(domainSID, 1105)

	sd, err := BuildPrincipalSD(domainSID, [][]byte{a, b})
	if err != nil {
		t.Fatalf("BuildPrincipalSD: %v", err)
	}

	got, err := PrincipalSIDs(sd)
	if err != nil {
		t.Fatalf("PrincipalSIDs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d principals, want 2", len(got))
	}
	if !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Errorf("principals did not round trip")
	}
}

func TestBuildPrincipalSDOwnerIsDomainAdmins(t *testing.T) {
	sd, err := BuildPrincipalSD(domainSID, [][]byte{sidWithRID(domainSID, 1104)})
	if err != nil {
		t.Fatalf("BuildPrincipalSD: %v", err)
	}
	p, err := parse(sd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	admins := sidWithRID(domainSID, 512)
	if !bytes.Equal(p.owner, admins) {
		t.Errorf("owner = %x, want Domain Admins %x", p.owner, admins)
	}
	if !bytes.Equal(p.group, admins) {
		t.Errorf("group = %x, want Domain Admins %x", p.group, admins)
	}
}

// An empty principal list is a real state, not an error: it is how a caller
// says "nobody may retrieve this password" or "nobody may impersonate here".
// It must serialise to a present-but-empty DACL, which denies everyone,
// rather than to an absent DACL, which allows everyone.
func TestBuildPrincipalSDEmptyIsAnEmptyDACLNotAnAbsentOne(t *testing.T) {
	sd, err := BuildPrincipalSD(domainSID, nil)
	if err != nil {
		t.Fatalf("BuildPrincipalSD: %v", err)
	}
	p, err := parse(sd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.control&controlDACLPresent == 0 {
		t.Fatal("DACL-present control bit is clear; an absent DACL grants everyone full control")
	}
	got, err := PrincipalSIDs(sd)
	if err != nil {
		t.Fatalf("PrincipalSIDs: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d principals, want 0", len(got))
	}
}

func TestPrincipalSIDsOnEmptyAttributeIsEmptyNotAnError(t *testing.T) {
	got, err := PrincipalSIDs(nil)
	if err != nil {
		t.Fatalf("PrincipalSIDs(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d principals, want 0", len(got))
	}
}

func TestBuildPrincipalSDRejectsAShortDomainSID(t *testing.T) {
	if _, err := BuildPrincipalSD([]byte{1, 0}, nil); err == nil {
		t.Fatal("want an error for a malformed domain SID, got nil")
	}
}
