package authorization

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// A raw query that names no grant reuses the caller's current covering grant
// (ADR-335 D5); pending, expired, foreign and non-covering grants are skipped.
func TestFindRawGrantReusesOnlyCurrentCoveringGrant(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	const root, caseID, artifactID, captureID = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"
	me := identity.Principal{Kind: identity.Human, Issuer: "https://idp.invalid", Subject: "me"}
	other := identity.Principal{Kind: identity.Human, Issuer: "https://idp.invalid", Subject: "other"}
	approved := &value.GrantDecision{Approved: true}
	raw := func(id string, requester identity.Principal, d *value.GrantDecision, expires time.Time, ops ...string) value.Grant {
		return value.Grant{ID: id, RootID: root, Kind: value.GrantRawQuery, Requester: requester, RequestedAt: now.Add(-time.Minute), Decision: d, ExpiresAt: expires,
			RawQuery: &value.RawQueryScope{CaseID: caseID, Operations: ops, Artifacts: []value.RawQueryArtifact{{Output: value.VerifiedOutput{ArtifactID: artifactID}}}}}
	}
	m := newMemoryGrants(func() time.Time { return now })
	for _, g := range []value.Grant{
		raw("00000000-0000-4000-8000-0000000000a1", me, nil, now.Add(time.Hour), "pcap_query"),
		raw("00000000-0000-4000-8000-0000000000a2", me, approved, now.Add(-time.Second), "pcap_query"),
		raw("00000000-0000-4000-8000-0000000000a3", other, approved, now.Add(time.Hour), "pcap_query"),
		raw("00000000-0000-4000-8000-0000000000a4", me, approved, now.Add(time.Hour), "download_artifact"),
	} {
		m.rows[g.ID] = g
	}
	s := GrantService{RootID: root, Store: m, Now: func() time.Time { return now }}
	caller := identity.Identity{Principal: me}
	if id, err := s.FindRawGrant(context.Background(), caller, caseID, artifactID, captureID, "pcap_query"); err != nil || id != "" {
		t.Fatal("reused a non-covering grant", id, err)
	}
	adhoc := value.Grant{ID: "00000000-0000-4000-8000-0000000000b1", RootID: root, Kind: value.GrantAdHocCapture, CaptureID: captureID, Requester: me, RequestedAt: now.Add(-time.Minute), Decision: approved, ExpiresAt: now.Add(time.Hour), ResultAccess: &value.ResultAccess{Operations: []string{"pcap_query"}}}
	m.rows[adhoc.ID] = adhoc
	if id, err := s.FindRawGrant(context.Background(), caller, caseID, artifactID, captureID, "pcap_query"); err != nil || id != adhoc.ID {
		t.Fatal("capture grant not reused", id, err)
	}
	covering := raw("00000000-0000-4000-8000-0000000000c1", me, approved, now.Add(time.Hour), "syscall_query", "pcap_query")
	m.rows[covering.ID] = covering
	if id, err := s.FindRawGrant(context.Background(), caller, caseID, artifactID, captureID, "syscall_query"); err != nil || id != covering.ID {
		t.Fatal("raw-query grant not reused", id, err)
	}
}
