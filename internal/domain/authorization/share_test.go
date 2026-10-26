package authorization

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// shareFixture: team-a holds evidence-owner on the target (the creator's
// pinned assignment); the recipient is a human outside every binding.
func shareFixture() (identity.Identity, identity.Identity, Projection, Retained, Share, time.Time) {
	creator, p, e, now := fixture()
	creator.Scopes = append(creator.Scopes, ShareScope)
	owner := p.Allows[0]
	owner.Audience.Role = "evidence-owner"
	owner.Audience.AssignmentID = "55555555-5555-5555-5555-555555555555"
	p.Allows = append(p.Allows, owner)
	e.Audience = append(e.Audience, owner.Audience)
	recipient := identity.Identity{Principal: identity.Principal{Issuer: creator.Principal.Issuer, Subject: "outsider", ClientID: "mcp", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Groups: []string{"outsiders"}, Policy: creator.Policy, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	s := Share{ID: "66666666-6666-6666-6666-666666666666", RootID: "77777777-7777-7777-7777-777777777777", ArtifactID: e.ArtifactID, CaseID: "88888888-8888-8888-8888-888888888888", Target: p.Target, Version: artifact.Digest{9},
		Creator: creator.Principal, Management: []artifact.AudienceAssignment{owner.Audience}, Recipients: []ShareRecipient{{"User", creator.Principal.Issuer, "outsider"}},
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Revision: 1, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	return creator, recipient, p, e, s, now
}

func TestShareManagementPinsOnlyCurrentOwnerAssignments(t *testing.T) {
	creator, _, p, e, s, now := shareFixture()
	r, owners := ShareManagement(creator, p, p.Target, &e, now)
	if !r.Eligible || len(owners) != 1 || owners[0] != s.Management[0] {
		t.Fatal("owner could not share", r.Reason, owners)
	}
	noScope := creator
	noScope.Scopes = []string{"evidence:read"}
	if r, _ := ShareManagement(noScope, p, p.Target, &e, now); r.Eligible || r.Reason != "InsufficientScope" {
		t.Fatal("share without evidence:share", r.Reason)
	}
	// A maintainer/reader without evidence-owner can read but not share.
	reader, p2, e2, _ := fixture()
	reader.Scopes = append(reader.Scopes, ShareScope)
	if r, _ := ShareManagement(reader, p2, p2.Target, &e2, now); r.Eligible || r.Reason != "NoOwnerAuthority" {
		t.Fatal("non-owner shared", r.Reason)
	}
	// An owner outside the retained audience (joined after capture) cannot share.
	late := e
	late.Audience = late.Audience[:1]
	if r, _ := ShareManagement(creator, p, p.Target, &late, now); r.Eligible {
		t.Fatal("owner outside the retained audience shared")
	}
}

func TestEvaluateShareMatrix(t *testing.T) {
	for _, c := range []struct {
		name   string
		edit   func(*identity.Identity, *Projection, *Retained, *Share)
		want   bool
		reason string
	}{
		{"recipient-user", nil, true, "Shared"},
		{"recipient-group", func(i *identity.Identity, _ *Projection, _ *Retained, s *Share) {
			s.Recipients = []ShareRecipient{{"Group", i.Principal.Issuer, "outsiders"}}
		}, true, "Shared"},
		{"group-churn-removes-access", func(i *identity.Identity, _ *Projection, _ *Retained, s *Share) {
			s.Recipients = []ShareRecipient{{"Group", i.Principal.Issuer, "outsiders"}}
			i.Groups = nil
		}, false, "NoEntitlement"},
		{"unrelated-principal", func(i *identity.Identity, _ *Projection, _ *Retained, _ *Share) { i.Principal.Subject = "stranger" }, false, "NoEntitlement"},
		{"foreign-issuer", func(i *identity.Identity, _ *Projection, _ *Retained, _ *Share) {
			i.Principal.Issuer = "https://other.example.invalid"
		}, false, "NoEntitlement"},
		{"workload-is-not-a-user", func(i *identity.Identity, _ *Projection, _ *Retained, _ *Share) { i.Principal.Kind = identity.Workload }, false, "NoEntitlement"},
		{"no-read-scope", func(i *identity.Identity, _ *Projection, _ *Retained, _ *Share) {
			i.Scopes = []string{"evidence:share"}
		}, false, "InsufficientScope"},
		{"expired", func(_ *identity.Identity, _ *Projection, _ *Retained, s *Share) {
			s.ExpiresAt = s.CreatedAt.Add(time.Minute)
		}, false, "ShareExpired"},
		{"revoked", func(_ *identity.Identity, _ *Projection, _ *Retained, s *Share) {
			s.RevokedAt, s.Revision = s.CreatedAt.Add(time.Second), 2
		}, false, "ShareRevoked"},
		{"deny-wins-user", func(i *identity.Identity, p *Projection, _ *Retained, _ *Share) {
			d := p.Allows[0]
			d.Audience.Kind, d.Audience.SubjectID, d.Audience.Role, d.Audience.AssignmentID = "User", i.Principal.Subject, "evidence-reader", "99999999-9999-9999-9999-999999999999"
			p.Denies = []CurrentAssignment{d}
		}, false, "ExplicitDeny"},
		{"deny-wins-group", func(i *identity.Identity, p *Projection, _ *Retained, _ *Share) {
			d := p.Allows[0]
			d.Audience.SubjectID, d.Audience.AssignmentID = "outsiders", "99999999-9999-9999-9999-999999999999"
			p.Denies = []CurrentAssignment{d}
		}, false, "ExplicitDeny"},
		{"manager-assignment-retired", func(_ *identity.Identity, p *Projection, _ *Retained, _ *Share) { p.Allows = p.Allows[:1] }, false, "ShareSuspended"},
		{"manager-regranted-is-new-assignment", func(_ *identity.Identity, p *Projection, _ *Retained, _ *Share) {
			p.Allows[1].Audience.AssignmentID = "abababab-abab-abab-abab-abababababab"
		}, false, "ShareSuspended"},
		{"manager-basis-changed", func(_ *identity.Identity, p *Projection, _ *Retained, _ *Share) {
			p.Allows[1].Audience.BasisDigest = artifact.Digest{7}
		}, false, "ShareSuspended"},
		{"manager-group-denied", func(_ *identity.Identity, p *Projection, _ *Retained, _ *Share) {
			d := p.Allows[1]
			d.Audience.AssignmentID = "99999999-9999-9999-9999-999999999999"
			p.Denies = []CurrentAssignment{d}
		}, false, "ShareSuspended"},
		{"creator-user-denied", func(_ *identity.Identity, p *Projection, _ *Retained, s *Share) {
			d := p.Allows[1]
			d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", s.Creator.Subject, "99999999-9999-9999-9999-999999999999"
			p.Denies = []CurrentAssignment{d}
		}, false, "ShareSuspended"},
		{"no-widening-to-other-artifact", func(_ *identity.Identity, _ *Projection, e *Retained, _ *Share) {
			e.ArtifactID = "12121212-1212-1212-1212-121212121212"
		}, false, "EvidenceUnavailable"},
		{"no-widening-to-other-target", func(_ *identity.Identity, _ *Projection, _ *Retained, s *Share) { s.Target.PodUID = "other-pod" }, false, "InvalidRequest"},
		{"manager-outside-retained-audience", func(_ *identity.Identity, _ *Projection, e *Retained, _ *Share) { e.Audience = e.Audience[:1] }, false, "ShareSuspended"},
		{"artifact-retention-ended", func(_ *identity.Identity, _ *Projection, e *Retained, _ *Share) {
			e.ExpiresAt = e.ExpiresAt.Add(-2 * time.Hour)
		}, false, "EvidenceUnavailable"},
		{"stale-share-read", func(_ *identity.Identity, _ *Projection, _ *Retained, s *Share) {
			s.ObservedAt = s.ObservedAt.Add(-6 * time.Second)
		}, false, "ShareUnavailable"},
		{"raw-data-class", func(_ *identity.Identity, _ *Projection, e *Retained, _ *Share) { e.DataClass = "raw" }, false, "RawAccessUnsupported"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, recipient, p, e, s, now := shareFixture()
			if c.edit != nil {
				c.edit(&recipient, &p, &e, &s)
			}
			r := EvaluateShare(recipient, p, p.Target, &e, s, now)
			if r.Eligible != c.want || r.Reason != c.reason {
				t.Fatalf("eligible=%t reason=%s want %t %s", r.Eligible, r.Reason, c.want, c.reason)
			}
			if r.Eligible && (r.ValidUntil.After(s.ValidUntil) || r.ValidUntil.After(s.ExpiresAt) || len(r.ContributingAssignments) != 1) {
				t.Fatal("shared result outlives its share or lost the manager provenance", r)
			}
		})
	}
}

func TestShareNeverGrantsOrdinaryOperations(t *testing.T) {
	_, recipient, p, e, s, now := shareFixture()
	if !EvaluateShare(recipient, p, p.Target, &e, s, now).Eligible {
		t.Fatal("fixture")
	}
	recipient.Scopes = append(recipient.Scopes, "evidence:download", "evidence:capture")
	for _, op := range []Operation{ReadApproved, DownloadApproved, CollectContext} {
		var retained *Retained
		if op != CollectContext {
			retained = &e
		}
		if Evaluate(recipient, p, op, p.Target, retained, now).Eligible || ScopeEligibility(recipient, p, op, p.Target, now).Eligible {
			t.Fatal("a recipient gained an ordinary operation", op)
		}
	}
}

func TestShareValidity(t *testing.T) {
	_, _, _, _, s, _ := shareFixture()
	for name, edit := range map[string]func(*Share){
		"too-long":          func(s *Share) { s.ExpiresAt = s.CreatedAt.Add(ShareMaxLifetime + time.Second) },
		"foreign-recipient": func(s *Share) { s.Recipients[0].Issuer = "https://other.example.invalid" },
		"display-name":      func(s *Share) { s.Recipients[0].Kind = "Name" },
		"non-owner-manager": func(s *Share) { s.Management[0].Role = "evidence-reader" },
		"revoked-revision":  func(s *Share) { s.RevokedAt = s.CreatedAt },
		"workload-creator":  func(s *Share) { s.Creator.Kind = identity.Workload },
		"too-many-recipients": func(s *Share) {
			for len(s.Recipients) <= ShareMaxRecipients {
				s.Recipients = append(s.Recipients, ShareRecipient{"Group", s.Creator.Issuer, string(rune('a' + len(s.Recipients)))})
			}
		},
	} {
		c := s
		c.Recipients = append([]ShareRecipient(nil), s.Recipients...)
		c.Management = append([]artifact.AudienceAssignment(nil), s.Management...)
		edit(&c)
		if c.Valid() {
			t.Fatal("invalid share accepted", name)
		}
	}
	if !s.Valid() {
		t.Fatal("fixture")
	}
}
