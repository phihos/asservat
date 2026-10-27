package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestPolicySharingStateIsDerived(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	creator := identity.Principal{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "mcp", Kind: identity.Human}
	in := PolicyShareInstruction{Creator: creator, Management: []artifact.AudienceAssignment{{Kind: "Group", Issuer: creator.Issuer, SubjectID: "team-a", Role: "evidence-owner", BasisKind: "AccessBinding", BasisUID: "b", AssignmentID: "55555555-5555-4555-8555-555555555555"}},
		Recipients: []authorization.ShareRecipient{{Kind: "Group", Issuer: creator.Issuer, ID: "incident"}}, MaxCaptures: 2, NotAfter: now.Add(time.Hour)}
	if !in.Valid() {
		t.Fatal("valid instruction refused")
	}
	for _, c := range []struct {
		spent              int64
		revoked            bool
		at                 time.Time
		accepted, observed int64
		want               string
	}{
		{0, false, now, 1, 1, PolicySharingActive},
		{2, false, now, 1, 1, PolicySharingLimitReached},
		{1, false, now.Add(time.Hour), 1, 1, PolicySharingExpired},
		{1, false, now, 1, 2, PolicySharingStopped},
		{2, true, now.Add(2 * time.Hour), 1, 2, PolicySharingRevoked},
	} {
		s := PolicySharingStatus{Instruction: in, Spent: c.spent}
		if c.revoked {
			s.RevokedAt = now
		}
		if got := s.State(c.at, c.accepted, c.observed); got != c.want {
			t.Fatalf("%+v: got %s", c, got)
		}
	}
	bad := in
	bad.Recipients = []authorization.ShareRecipient{{Kind: "Group", Issuer: "https://other.example.invalid", ID: "x"}}
	if bad.Valid() {
		t.Fatal("recipient of another issuer than the creator accepted")
	}
	bad = in
	bad.MaxCaptures = PolicyShareMaxCaptures + 1
	if bad.Valid() {
		t.Fatal("more than 100 captures accepted")
	}
	bad = in
	bad.Management = nil
	if bad.Valid() {
		t.Fatal("unmanaged instruction accepted")
	}
}
