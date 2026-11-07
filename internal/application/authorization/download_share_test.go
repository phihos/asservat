package authorization

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// shareDownloadFixture turns the download fixture's caller into a recipient
// without whole-pod rights: team "owners" holds evidence-owner and one share
// of exactly this artifact names user "outsider" (ADR-233).
func shareDownloadFixture() (*downloadAuthorityFixture, *projectionShares, ContextDownloadAuthority, artifact.DownloadScope) {
	f, s, scope := newDownloadAuthorityFixture()
	owner := f.p.Allows[0]
	owner.Audience.SubjectID, owner.Audience.Role, owner.Audience.AssignmentID = "owners", "evidence-owner", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	f.p.Allows = append(f.p.Allows, owner)
	f.record.Audience = append(append([]artifact.AudienceAssignment(nil), f.record.Audience...), owner.Audience)
	f.record.CaseID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	f.i.Principal.Subject, f.i.Groups = "outsider", []string{"outsiders"}
	f.environment.Principal = f.i.Principal
	scope.Principal = f.i.Principal
	creator := identity.Principal{Issuer: f.i.Principal.Issuer, Subject: "owner", ClientID: "mcp", Kind: identity.Human}
	share := value.Share{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", RootID: scope.RootID, ArtifactID: scope.ArtifactID, CaseID: f.record.CaseID, Target: f.p.Target, Version: scope.Version, Creator: creator,
		Management: []artifact.AudienceAssignment{owner.Audience}, Recipients: []value.ShareRecipient{{Kind: "User", Issuer: creator.Issuer, ID: "outsider"}},
		CreatedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), Revision: 1}
	shares := &projectionShares{now: func() time.Time { return f.now }, rows: []value.Share{share}}
	s.Shares = shares
	return f, shares, s, scope
}

func TestContextDownloadAuthorityAdmitsShareRecipient(t *testing.T) {
	f, shares, s, scope := shareDownloadFixture()
	out, err := s.CheckDownload(context.Background(), "synthetic-token", scope)
	if err != nil || !out.Valid(f.now) || out.Scope != scope || shares.reads != 2 || f.catalogReads != 1 {
		t.Fatalf("recipient download: %v reads=%d catalog=%d", err, shares.reads, f.catalogReads)
	}
	// Without the share branch the same caller is refused before the catalog.
	f2, _, s2, scope2 := shareDownloadFixture()
	s2.Shares = nil
	if _, err := s2.CheckDownload(context.Background(), "synthetic-token", scope2); err == nil || f2.catalogReads != 0 {
		t.Fatal("recipient downloaded without a share reader")
	}
}

func TestContextDownloadAuthorityRefusesShareBeforeCatalog(t *testing.T) {
	for _, name := range []string{"no-share", "deny", "no-download-scope", "other-version", "revoked", "expired", "suspended", "other-recipient"} {
		t.Run(name, func(t *testing.T) {
			f, shares, s, scope := shareDownloadFixture()
			switch name {
			case "no-share":
				shares.rows = nil
			case "deny":
				d := f.p.Allows[0]
				d.Audience.Kind, d.Audience.SubjectID, d.Audience.AssignmentID = "User", "outsider", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
				f.p.Denies = []value.CurrentAssignment{d}
			case "no-download-scope":
				f.i.Scopes = []string{"evidence:read"}
			case "other-version":
				shares.rows[0].Version = artifact.Digest{9}
			case "revoked":
				shares.rows[0].RevokedAt, shares.rows[0].Revision = f.now, 2
			case "expired":
				shares.rows[0].ExpiresAt = f.now
			case "suspended":
				f.p.Allows = f.p.Allows[:1]
			case "other-recipient":
				shares.rows[0].Recipients[0].ID = "someone-else"
			}
			if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil || f.catalogReads != 0 || f.environmentReads != 0 {
				t.Fatal("refused recipient reached the catalog", err)
			}
		})
	}
}

func TestContextDownloadAuthorityShareRevokedDuringCheck(t *testing.T) {
	f, shares, s, scope := shareDownloadFixture()
	shares.onRead = func(n int) {
		if n == 1 {
			shares.rows[0].RevokedAt, shares.rows[0].Revision = f.now, 2
		}
	}
	if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil {
		t.Fatal("revocation during the check was ignored")
	}
	// The share binds the case of the artifact it names.
	f, shares, s, scope = shareDownloadFixture()
	shares.rows[0].CaseID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	if _, err := s.CheckDownload(context.Background(), "synthetic-token", scope); err == nil {
		t.Fatal("share of another case admitted")
	}
}

// A started response continues to AccessUntil without another check
// (ADR-312), so a shared decision's AccessUntil ends with its share.
func TestSharedDownloadAccessEndsWithShare(t *testing.T) {
	f, shares, s, scope := shareDownloadFixture()
	shares.rows[0].ExpiresAt = f.now.Add(20 * time.Second)
	a, err := s.CheckDownload(t.Context(), "synthetic-token", scope)
	if err != nil || !a.AccessUntil.Equal(shares.rows[0].ExpiresAt) {
		t.Fatal("shared access not bounded by its share", err, a.AccessUntil)
	}
}
