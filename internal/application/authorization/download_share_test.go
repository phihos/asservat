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

// A response-owned shared entitlement uses the existing 30-second
// reconstruction interval (ADR-220): a revocation refuses at the next
// reconstruction, never later, and the entitlement never outlives its share.
func TestDownloadResponseShareRecheck(t *testing.T) {
	for _, name := range []string{"revoked", "expired"} {
		t.Run(name, func(t *testing.T) {
			f, shares, s, scope := shareDownloadFixture()
			start := f.now
			if name == "expired" {
				shares.rows[0].ExpiresAt = start.Add(20 * time.Second)
			}
			owner, err := s.NewDownloadResponse(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			current := credentialIdentity{f, "synthetic"}
			currentDownloadResponseFacts(f, start)
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || shares.reads != 2 {
				t.Fatal("first recipient check", err, shares.reads)
			}
			if name == "revoked" {
				shares.rows[0].RevokedAt, shares.rows[0].Revision = start.Add(time.Second), 2
			}
			currentDownloadResponseFacts(f, start.Add(10*time.Second))
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err != nil || shares.reads != 2 {
				t.Fatal("entitlement within the recheck interval", err, shares.reads)
			}
			at := start.Add(30 * time.Second)
			if name == "expired" {
				at = start.Add(20 * time.Second)
			}
			currentDownloadResponseFacts(f, at)
			if _, err := owner.CheckDownloadCurrent(t.Context(), current, scope); err == nil || shares.reads != 3 {
				t.Fatal("share not rechecked at reconstruction", err, shares.reads)
			}
		})
	}
}
