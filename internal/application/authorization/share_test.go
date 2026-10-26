package authorization

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// projectionShares is an in-memory ShareReader for the projection
// authority tests; reads stamp a five-second observation.
type projectionShares struct {
	now    func() time.Time
	rows   []value.Share
	reads  int
	onRead func(int)
}

func (s *projectionShares) RecipientShares(_ context.Context, artifactID string, caller identity.Identity) ([]value.Share, error) {
	s.reads++
	if s.onRead != nil {
		s.onRead(s.reads)
	}
	keys := value.RecipientKeys(caller)
	var out []value.Share
	for _, r := range s.rows {
		match := false
		for _, x := range r.Recipients {
			match = match || slices.Contains(keys, x.Key())
		}
		if r.ArtifactID == artifactID && r.RevokedAt.IsZero() && match {
			r.ObservedAt, r.ValidUntil = s.now(), s.now().Add(5*time.Second)
			out = append(out, r)
		}
	}
	return out, nil
}

// shareProjectionFixture turns the projection fixture's caller into a
// recipient: team "owners" holds evidence-owner and one share names "outsider".
func shareProjectionFixture() (*projectionFixture, *projectionShares, ContextProjectionAuthority, value.Share) {
	f, s, scope := newProjectionFixture()
	owner := f.permission.Allows[0]
	owner.Audience.SubjectID, owner.Audience.Role, owner.Audience.AssignmentID = "owners", "evidence-owner", projectionTestID(40)
	f.permission.Allows = append(f.permission.Allows, owner)
	f.record.Audience = append(f.record.Audience, owner.Audience)
	f.identity.Principal.Subject, f.identity.Groups = "outsider", []string{"outsiders"}
	f.environment.Principal = f.identity.Principal
	creator := identity.Principal{Issuer: f.identity.Principal.Issuer, Subject: "owner", ClientID: "mcp", Kind: identity.Human}
	target := f.permission.Target
	share := value.Share{ID: projectionTestID(41), RootID: scope.RootID, ArtifactID: scope.ArtifactID, CaseID: scope.CaseID, Target: target, Version: scope.Version, Creator: creator,
		Management: []artifact.AudienceAssignment{owner.Audience}, Recipients: []value.ShareRecipient{{Kind: "User", Issuer: creator.Issuer, ID: "outsider"}},
		CreatedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Revision: 1}
	shares := &projectionShares{now: func() time.Time { return f.now }, rows: []value.Share{share}}
	s.Shares = shares
	return f, shares, s, share
}

func TestContextProjectionAuthorityAdmitsRecipientOfExactShare(t *testing.T) {
	f, shares, s, _ := shareProjectionFixture()
	_, _, scope := newProjectionFixture()
	scope.Principal = f.identity.Principal
	out, err := s.CheckProjectionCurrent(context.Background(), f, scope)
	if err != nil || !out.Valid(f.now) || shares.reads != 2 {
		t.Fatalf("recipient inspection: %v reads=%d", err, shares.reads)
	}
	// The decision binds the share: the same read as an ordinary reader differs.
	for _, name := range []string{"revoked-during-read", "no-share", "deny"} {
		t.Run(name, func(t *testing.T) {
			f, shares, s, _ := shareProjectionFixture()
			switch name {
			case "revoked-during-read":
				shares.onRead = func(n int) {
					if n == 1 {
						shares.rows[0].RevokedAt, shares.rows[0].Revision = f.now, 2
					}
				}
			case "no-share":
				shares.rows = nil
			case "deny":
				d := f.permission.Allows[0]
				d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "outsider", projectionTestID(42)
				f.permission.Denies = []value.CurrentAssignment{d}
			}
			if _, err := s.CheckProjectionCurrent(context.Background(), f, scope); err == nil {
				t.Fatal("refused recipient inspected", name)
			}
			if name != "revoked-during-read" && f.counts["catalog"] != 0 {
				t.Fatal("catalog read before the share admitted the caller")
			}
		})
	}
}
