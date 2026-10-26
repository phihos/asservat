package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	configapp "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/catalog"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyEvidenceShare (ADR-232) runs the share ledger through the compiled
// hub-runtime grants on real PostgreSQL against an actually published
// artifact, the actual accepted permission projection and the case service:
// an unrelated principal is refused without a share, a recipient reads only
// its share, revocation concurrent with reads stops every later read,
// expiry ends a share, and a current Deny (or the loss of the pinned owner
// assignment) wins over every share.
func qualifyEvidenceShare(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, reader *postgres.ContextPublications) {
	t.Helper()
	role := narrowRole(t, ctx, admin, "share_hub_", "synthetic-share-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing compiled hub grants")
		}
		return grants
	})
	pool := poolFor(role, "synthetic-share-hub")
	t.Cleanup(pool.Close) // later subtests share the fixture's connection limit
	routes, err := postgres.NewContextCaseReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.NewEvidenceShares(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	cases := catalogapp.ContextCaseService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: reader, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Recovery: s.recovery.reader, Processing: processing, Shares: store, Now: time.Now}
	shares := sharing.Service{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: reader, Store: store, Recovery: s.recovery.reader, NewID: custodyID, Now: time.Now}
	issuer := s.a.Eligibility.VerifiedIdentity.Principal.Issuer
	batch := s.batch
	refresh := func() {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		b := batch
		b.Initial = nil
		b.ObservedAt, b.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	as := func(subject string, groups []string, scopes ...string) identities.CurrentIdentity {
		t.Helper()
		refresh()
		now := time.Now().UTC().Truncate(time.Microsecond)
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Groups, i.Scopes = subject, groups, scopes
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	owner := func() identities.CurrentIdentity {
		return as("synthetic-share-owner", []string{"other-owners"}, "evidence:read", authorization.ShareScope)
	}
	recipient := func() identities.CurrentIdentity { return as("synthetic-recipient", nil, "evidence:read") }
	stranger := func() identities.CurrentIdentity { return as("synthetic-stranger", nil, "evidence:read") }
	reads := func(source identities.CurrentIdentity) bool {
		t.Helper()
		view, err := cases.GetContextCase(ctx, source, e.CaseID)
		if err == nil {
			if len(view.Artifacts) != 1 || view.Artifacts[0].ArtifactID != e.Registration.Location.ArtifactID || !view.Artifacts[0].Shared {
				t.Fatal("recipient view exceeds its share", view)
			}
			return true
		}
		if err != value.ErrUnavailable || view.CaseID != "" {
			t.Fatal("refusal disclosed a case", view, err)
		}
		return false
	}
	verified, err := reader.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	create := func(key string, recipients []authorization.ShareRecipient, expires time.Time) authorization.Share {
		t.Helper()
		share, replay, err := shares.Create(ctx, owner(), sharing.CreateInput{CaseID: e.CaseID, ArtifactID: e.Registration.Location.ArtifactID, Version: verified.Version, Recipients: recipients, ExpiresAt: expires, Reason: "synthetic incident review", IdempotencyKey: key})
		if err != nil || replay || share.Revision != 1 || len(share.Management) != 1 || share.Management[0].SubjectID != "other-owners" {
			t.Fatal("create share", err, replay, share)
		}
		return share
	}
	user := []authorization.ShareRecipient{{Kind: "User", Issuer: issuer, ID: "synthetic-recipient"}}

	// Before any share: refused, like any unrelated principal.
	if reads(recipient()) || reads(stranger()) {
		t.Fatal("principal without a share read the case")
	}
	// Only evidence-owner with evidence:share may share; the maintainer may not.
	if _, _, err := shares.Create(ctx, as("synthetic-maintainer", []string{"maintainers"}, "evidence:read", authorization.ShareScope), sharing.CreateInput{CaseID: e.CaseID, ArtifactID: e.Registration.Location.ArtifactID, Version: verified.Version, Recipients: user, ExpiresAt: time.Now().Add(time.Hour), Reason: "r", IdempotencyKey: "maintainer"}); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("non-owner shared", err)
	}
	firstExpiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	first := create("share-1", user, firstExpiry)
	same := sharing.CreateInput{CaseID: e.CaseID, ArtifactID: e.Registration.Location.ArtifactID, Version: verified.Version, Recipients: user, ExpiresAt: firstExpiry, Reason: "synthetic incident review", IdempotencyKey: "share-1"}
	if again, replay, err := shares.Create(ctx, owner(), same); err != nil || !replay || again.ID != first.ID {
		t.Fatal("same-key create did not replay", err, replay)
	}
	same.Reason = "another reason"
	if _, _, err := shares.Create(ctx, owner(), same); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("changed request under the same key", err)
	}
	if !reads(recipient()) {
		t.Fatal("recipient could not read the shared artifact")
	}
	if reads(stranger()) {
		t.Fatal("unrelated principal read through another principal's share")
	}
	if got, _, err := shares.List(ctx, recipient(), "received", 20); err != nil || len(got) != 1 || got[0].Share.ID != first.ID {
		t.Fatal("received list", err, got)
	}
	// Rows are immutable apart from one revocation, also for the runtime role.
	for _, sql := range []string{"UPDATE evidence_share SET expires_at=expires_at+interval '1 day' WHERE id=$1", "DELETE FROM evidence_share WHERE id=$1", "UPDATE evidence_share SET recipient_keys=recipient_keys WHERE id=$1"} {
		_, err := pool.Exec(ctx, sql, first.ID)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("runtime role changed a share %s: %v", sql, err)
		}
	}
	if _, err := admin.Exec(ctx, "UPDATE evidence_share SET expires_at=expires_at+interval '1 hour' WHERE id=$1", first.ID); err == nil {
		t.Fatal("share extended in place")
	}

	// Concurrent revoke vs read: no read that starts after the revocation
	// returned may succeed.
	recipientRows := func() bool {
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Groups, i.Scopes = "synthetic-recipient", nil, []string{"evidence:read"}
		i.VerifiedAt, i.ValidUntil = time.Now().UTC(), time.Now().UTC().Add(5*time.Second)
		rows, err := store.RecipientShares(ctx, e.Registration.Location.ArtifactID, i)
		if err != nil {
			t.Error("recipient lookup", err)
		}
		return len(rows) > 0
	}
	var revokedAt time.Time
	var mu sync.Mutex
	var late int
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				started := time.Now()
				found := recipientRows()
				mu.Lock()
				if found && !revokedAt.IsZero() && started.After(revokedAt) {
					late++
				}
				mu.Unlock()
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	revoked, replay, err := shares.Revoke(ctx, owner(), first.ID, 1, "revoke-1")
	mu.Lock()
	revokedAt = time.Now()
	mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	if err != nil || replay || revoked.Revision != 2 || late != 0 {
		t.Fatal("revocation", err, replay, revoked.Revision, "reads after revocation:", late)
	}
	if reads(recipient()) {
		t.Fatal("revoked share still readable")
	}
	if again, replay, err := shares.Revoke(ctx, owner(), first.ID, 1, "revoke-1"); err != nil || !replay || again.Revision != 2 {
		t.Fatal("revocation replay", err, replay)
	}
	if _, _, err := shares.Revoke(ctx, owner(), first.ID, 1, "revoke-other"); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("second revocation under another key", err)
	}
	if _, _, err := shares.Revoke(ctx, as("synthetic-other-owner", []string{"other-owners"}, "evidence:read", authorization.ShareScope), first.ID, 2, "foreign"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("non-creator revoked", err)
	}

	// Expiry ends a share at its deadline without any write.
	short := create("share-short", user, time.Now().Add(2*time.Second))
	if !reads(recipient()) {
		t.Fatal("short share unreadable before expiry")
	}
	time.Sleep(time.Until(short.ExpiresAt) + 100*time.Millisecond)
	if reads(recipient()) {
		t.Fatal("expired share still readable")
	}
	if owned, _, err := shares.List(ctx, owner(), "owned", 20); err != nil || len(owned) != 2 || owned[0].Share.ID != short.ID || owned[0].Phase != authorization.ShareExpired || owned[1].Phase != authorization.ShareRevoked {
		t.Fatal("owned phases", err, owned)
	}

	// A group share and a user share; then one accepted batch denies the user
	// and retires the owners' assignment: deny wins, and the group share is
	// Suspended (its pinned owner assignment is gone).
	create("share-user", user, time.Now().Add(time.Hour))
	create("share-group", []authorization.ShareRecipient{{Kind: "Group", Issuer: issuer, ID: "synthetic-reviewers"}}, time.Now().Add(time.Hour))
	reviewer := func() identities.CurrentIdentity {
		return as("synthetic-reviewer", []string{"synthetic-reviewers"}, "evidence:read")
	}
	if !reads(recipient()) || !reads(reviewer()) {
		t.Fatal("active user/group shares unreadable")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	changed := batch
	changed.Initial = nil
	changed.RequestID, changed.InputDigest = custodyID(), artifact.Digest{97}
	changed.ObservedAt, changed.FreshUntil = now, now.Add(5*time.Second)
	deny := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "share-deny-1", SpecDigest: artifact.Digest{96}}, Scope: batch.Bases[0].Scope, Effect: "Deny", Subjects: []cfg.Subject{{Kind: "User", Issuer: issuer, ID: "synthetic-recipient"}}, Roles: []string{"evidence-reader"}}
	deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
	changed.Bases = []cfg.PermissionBasis{batch.Bases[0], deny}
	if _, err := s.p.AcceptPermissions(ctx, changed); err != nil {
		t.Fatal(err)
	}
	identityAt := func(subject string, groups []string) identities.CurrentIdentity {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Groups, i.Scopes = subject, groups, []string{"evidence:read"}
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	if view, err := cases.GetContextCase(ctx, identityAt("synthetic-recipient", nil), e.CaseID); err != value.ErrUnavailable || view.CaseID != "" {
		t.Fatal("denied recipient read through a share", view, err)
	}
	if view, err := cases.GetContextCase(ctx, identityAt("synthetic-reviewer", []string{"synthetic-reviewers"}), e.CaseID); err != value.ErrUnavailable || view.CaseID != "" {
		t.Fatal("share without a current owner assignment stayed readable", view, err)
	}
	t.Log("evidence share: refusal without share, recipient-only read, concurrent revocation, expiry, deny and owner-assignment loss qualified on real PostgreSQL")
}
