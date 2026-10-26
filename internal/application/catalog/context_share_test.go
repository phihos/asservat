package catalog

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

// shareFake is the ADR-232 recipient lookup: rows of exactly one artifact.
type shareFake struct {
	f          *caseFixture
	rows       []authorization.Share
	reads      int
	keys       [][]string
	afterFirst func()
	fail       bool
}

func (s *shareFake) RecipientShares(_ context.Context, artifactID string, caller identity.Identity) ([]authorization.Share, error) {
	s.reads++
	s.keys = append(s.keys, authorization.RecipientKeys(caller))
	if s.fail {
		return nil, errors.New("private share store")
	}
	var out []authorization.Share
	for _, r := range s.rows {
		if r.ArtifactID == artifactID && r.RevokedAt.IsZero() {
			r.ObservedAt, r.ValidUntil = s.f.now, s.f.now.Add(5*time.Second)
			out = append(out, r)
		}
	}
	if s.reads == 1 && s.afterFirst != nil {
		s.afterFirst()
	}
	return out, nil
}

// newShareCaseFixture: the caller is an outsider with no binding; team
// "owners" holds evidence-owner on the target and is in the retained audience;
// one share of the case's artifact names the outsider.
func newShareCaseFixture() (*caseFixture, *shareFake, ContextCaseService) {
	f, s := newCaseFixture()
	owner := f.p.Allows[0]
	owner.Audience.SubjectID, owner.Audience.Role, owner.Audience.AssignmentID = "owners", "evidence-owner", caseID(12)
	f.p.Allows = append(f.p.Allows, owner)
	f.record.Audience = append(f.record.Audience, owner.Audience)
	f.i.Principal.Subject, f.i.Groups = "outsider", []string{"outsiders"}
	creator := identity.Principal{Issuer: f.i.Principal.Issuer, Subject: "owner", ClientID: "mcp", Kind: identity.Human}
	route := f.routes.Routes[0]
	share := authorization.Share{ID: caseID(30), RootID: caseID(1), ArtifactID: route.ArtifactID, CaseID: f.routes.CaseID, Target: route.Target, Version: f.record.Version,
		Creator: creator, Management: []artifact.AudienceAssignment{owner.Audience}, Recipients: []authorization.ShareRecipient{{Kind: "User", Issuer: creator.Issuer, ID: "outsider"}},
		CreatedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Revision: 1}
	shares := &shareFake{f: f, rows: []authorization.Share{share}}
	s.Shares = shares
	return f, shares, s
}

func TestContextCaseRecipientReadsOnlyTheSharedArtifact(t *testing.T) {
	f, shares, s := newShareCaseFixture()
	got, err := s.GetContextCase(context.Background(), f, f.routes.CaseID)
	if err != nil || len(got.Artifacts) != 1 || !got.Artifacts[0].Shared || got.Artifacts[0].Version != f.record.Version {
		t.Fatalf("recipient view: %+v %v", got, err)
	}
	// One lookup before the catalog read and one re-read before returning.
	if shares.reads != 2 || f.catalogReads != 1 {
		t.Fatal("share reads", shares.reads, f.catalogReads)
	}
	// Ordinary readers keep ordinary access without any share lookup.
	f2, shares2, s2 := newShareCaseFixture()
	f2.i.Principal.Subject, f2.i.Groups = "developer", []string{"team"}
	if got, err := s2.GetContextCase(context.Background(), f2, f2.routes.CaseID); err != nil || got.Artifacts[0].Shared || shares2.reads != 0 {
		t.Fatal("ordinary reader used the share branch", err, shares2.reads)
	}
}

func TestContextCaseRecipientRefusals(t *testing.T) {
	for _, c := range []struct {
		name          string
		edit          func(*caseFixture, *shareFake)
		catalogBefore bool // the refusal happens only after the catalog read
	}{
		{"no-share", func(_ *caseFixture, s *shareFake) { s.rows = nil }, false},
		{"unrelated-principal", func(f *caseFixture, _ *shareFake) { f.i.Principal.Subject, f.i.Groups = "stranger", nil }, false},
		{"share-of-another-case", func(_ *caseFixture, s *shareFake) { s.rows[0].CaseID = caseID(31) }, false},
		{"expired", func(f *caseFixture, s *shareFake) { s.rows[0].ExpiresAt = f.now }, false},
		{"revoked", func(f *caseFixture, s *shareFake) { s.rows[0].RevokedAt, s.rows[0].Revision = f.now, 2 }, false},
		{"deny-wins", func(f *caseFixture, _ *shareFake) {
			d := f.p.Allows[0]
			d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "outsider", caseID(13)
			f.p.Denies = []authorization.CurrentAssignment{d}
		}, false},
		{"manager-lost", func(f *caseFixture, _ *shareFake) { f.p.Allows = f.p.Allows[:1] }, false},
		{"changed-version", func(_ *caseFixture, s *shareFake) { s.rows[0].Version = artifact.Digest{9} }, true},
		{"manager-outside-retained-audience", func(f *caseFixture, _ *shareFake) { f.record.Audience = f.record.Audience[:1] }, true},
		{"share-store-unavailable", func(_ *caseFixture, s *shareFake) { s.fail = true }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, shares, s := newShareCaseFixture()
			c.edit(f, shares)
			got, err := s.GetContextCase(context.Background(), f, f.routes.CaseID)
			if err != value.ErrUnavailable || got.CaseID != "" {
				t.Fatal("recipient refusal disclosed a case", got, err)
			}
			if !c.catalogBefore && f.catalogReads != 0 {
				t.Fatal("evidence lookup before the share admitted the caller", f.catalogReads)
			}
		})
	}
}

func TestContextCaseRevocationDuringReadRefuses(t *testing.T) {
	f, shares, s := newShareCaseFixture()
	shares.afterFirst = func() { shares.rows[0].RevokedAt, shares.rows[0].Revision = f.now, 2 }
	if got, err := s.GetContextCase(context.Background(), f, f.routes.CaseID); err != value.ErrUnavailable || got.CaseID != "" {
		t.Fatal("revoked share still answered", got, err)
	}
	f2, shares2, s2 := newShareCaseFixture()
	f2.afterFinalPermissions = func() {
		d := f2.p.Allows[0]
		d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "Group", "outsiders", caseID(14)
		f2.p.Denies = []authorization.CurrentAssignment{d}
	}
	if got, err := s2.GetContextCase(context.Background(), f2, f2.routes.CaseID); err != value.ErrUnavailable || got.CaseID != "" || shares2.reads < 1 {
		t.Fatal("deny added during the read did not win", got, err)
	}
}
