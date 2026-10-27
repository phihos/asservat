package integration

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retentionPreviewAuthority stands in for the browser identity, the protected
// fleet administration and the recovery proof; the catalog read and the
// EvidenceRetentionPolicy decoder are the production adapters.
type retentionPreviewAuthority struct {
	installation string
	now          time.Time
}

func (a retentionPreviewAuthority) ResolveIdentity(context.Context) (identity.Identity, error) {
	n := time.Now().UTC()
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "operator", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}, nil
}
func (a retentionPreviewAuthority) FleetAdministration(context.Context) (fleet.Administration, error) {
	n := time.Now().UTC()
	return fleet.Administration{InstallationID: a.installation, IssuerEpoch: a.installation, Issuer: "https://id.example.invalid", Revision: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{2}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second),
		Clients: []string{"console"}, Groups: []string{"platform-admins"}, DeliveryProfiles: []string{"kv"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}, nil
}
func (a retentionPreviewAuthority) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	n := time.Now().UTC()
	return artifact.RecoveryProof{InstallationID: a.installation, IssuerEpoch: a.installation, Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}

// retentionPreviewSpec is a hub baseline EvidenceRetentionPolicy spec with
// the given evidence maximum and a five-minute cleanup budget.
func retentionPreviewSpec(maximum int64) []byte {
	m := strconv.FormatInt(maximum, 10)
	d := strconv.FormatInt(min(maximum, 3600), 10)
	return []byte(`{"scope":{},"purposeRef":"diagnostics","defaults":{"evidenceSeconds":` + d + `,"caseMetadataSeconds":3600,"auditMetadataSeconds":3600},` +
		`"maxima":{"evidenceSeconds":` + m + `,"caseMetadataSeconds":86400,"auditMetadataSeconds":86400},"rules":[],"deletionBudgetSeconds":` + strconv.FormatInt(min(300, maximum-1), 10) + `,"legalExceptions":"disabled"}`)
}

// admitRetentionPreviewContexts admits n further contexts of one scenario and
// returns their registrations.
// The scenario's synthetic target and permission observations last five
// seconds, so admission stops early once budget has elapsed.
func admitRetentionPreviewContexts(t *testing.T, ctx context.Context, s captureAdmissionScenario, n int, budget time.Duration) []artifact.Registration {
	t.Helper()
	out := make([]artifact.Registration, 0, n)
	retention, refreshed, started := s.a.Plan.Input.Retention, time.Now(), time.Now()
	for i := 0; i < n && time.Since(started) < budget; i++ {
		// The scenario's retention resolution and source observation last
		// five seconds; a longer run renews both for the original anchor.
		if time.Since(refreshed) > 2*time.Second {
			policies, err := s.retention.policies(ctx)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			if retention, err = privacy.Resolve(policies, privacy.Input{Target: s.a.Plan.Input.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: s.a.Registration.AnchorAt}, now); err != nil {
				t.Fatal(err)
			}
			refreshed = time.Now()
		}
		a := s.a
		a.IdempotencyKey = custodyID()
		a.SubmissionDigest[1], a.SubmissionDigest[2] = byte(i), byte(i>>8)
		input := a.Plan.Input
		input.CaptureID = custodyID()
		input.Retention = retention
		var err error
		a.Plan, err = planning.CompileContext(input, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		a.Registration.Location.ArtifactID = custodyID()
		a.Registration.Location.AttemptID = custodyID()
		accepted, err := s.s.AdmitContext(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, accepted.Expectation.Registration)
	}
	return out
}

// qualifyRetentionPreview (ADR-240) runs the retention impact preview on real
// PostgreSQL: the production catalog read with a role limited to the hub
// metadata reader's tables, the production policy decoder and the catch-up's
// deadline functions.
func qualifyRetentionPreview(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	previewPool := poolFor("retention_preview_read_runtime", "synthetic-retention-preview-read")
	defer previewPool.Close()
	decoder, err := kube.NewRetentionPolicySpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	effective := func(t *testing.T, root string) map[string][2]time.Time {
		t.Helper()
		rows, err := admin.Query(ctx, "SELECT a.id::text,a.effective_expires_at,a.effective_delete_by FROM custody_attempt a JOIN context_capture c ON c.attempt_id=a.id WHERE c.root_id=$1", root)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][2]time.Time{}
		for rows.Next() {
			var id string
			var e, d time.Time
			if err = rows.Scan(&id, &e, &d); err != nil {
				t.Fatal(err)
			}
			out[id] = [2]time.Time{e, d}
		}
		return out
	}
	t.Run("retention-preview-shorten-lengthen-unknown-incomplete", func(t *testing.T) {
		s := create(t, 4)
		registrations := admitRetentionPreviewContexts(t, ctx, s, 3, time.Minute)
		if len(registrations) != 3 {
			t.Fatal("fixture admission too slow")
		}
		if _, err := previewPool.Exec(ctx, "UPDATE custody_attempt SET effective_expires_at=effective_expires_at"); err == nil {
			t.Fatal("preview role can change deadlines")
		}
		catalog, err := postgres.NewRetentionSources(ctx, previewPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		installation := s.recovery.installation
		previewer := privacyapp.RetentionPreviewer{InstallationID: installation, Administration: retentionPreviewAuthority{installation: installation}, Catalog: catalog, Decoder: decoder, Recovery: retentionPreviewAuthority{installation: installation}, Now: time.Now}
		authority := retentionPreviewAuthority{installation: installation}
		anchor := registrations[0].AnchorAt
		for _, r := range registrations {
			anchor = identity.Earlier(anchor, r.AnchorAt)
		}
		preview := func(t *testing.T, changes ...privacyapp.ProposedRetentionChange) privacy.RetentionPreview {
			t.Helper()
			if err := s.retention.observe(ctx); err != nil {
				t.Fatal(err)
			}
			p, _, err := previewer.Preview(ctx, authority, changes)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
		before := effective(t, s.a.RootID)
		var decisions int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM retention_decision WHERE root_id=$1", s.a.RootID).Scan(&decisions); err != nil || decisions != 0 {
			t.Fatal(decisions, err)
		}

		// Shortening the baseline to ten minutes moves every artifact's
		// deletion to anchor+10 min and its access end five minutes before.
		p := preview(t, privacyapp.ProposedRetentionChange{Action: "update", UID: "baseline", Spec: retentionPreviewSpec(600)})
		if !p.Complete() || p.Scanned != 3 || p.Affected != 3 || p.Unknown != 0 || p.ReadClosed != 0 || !p.EarliestDeleteBy.Equal(anchor.Add(10*time.Minute)) || !p.EarliestExpiresAt.Equal(anchor.Add(5*time.Minute)) || len(p.Groups) != 1 || p.Groups[0].Affected != 3 {
			t.Fatalf("shortening: %+v", p)
		}
		// Once a two-second maximum has passed, access ends and deletion is
		// due at once.
		time.Sleep(time.Until(anchor.Add(2100 * time.Millisecond)))
		if p = preview(t, privacyapp.ProposedRetentionChange{Action: "update", UID: "baseline", Spec: retentionPreviewSpec(2)}); p.Affected != 3 || p.ReadClosed != 3 || p.DeletionDue != 3 {
			t.Fatalf("immediate: %+v", p)
		}
		// Lengthening never moves a bound date.
		if p = preview(t, privacyapp.ProposedRetentionChange{Action: "update", UID: "baseline", Spec: retentionPreviewSpec(172800)}); !p.Complete() || p.Scanned != 3 || p.Affected != 0 || !p.EarliestDeleteBy.IsZero() {
			t.Fatalf("lengthening: %+v", p)
		}
		// A newly selected label selector needs historical labels: Unknown.
		labelled := []byte(`{"scope":{"namespaceSelector":{"matchLabels":{"team":"payments"}}},"purposeRef":"diagnostics","defaults":{"evidenceSeconds":60,"caseMetadataSeconds":3600,"auditMetadataSeconds":3600},` +
			`"maxima":{"evidenceSeconds":600,"caseMetadataSeconds":86400,"auditMetadataSeconds":86400},"rules":[],"deletionBudgetSeconds":300,"legalExceptions":"disabled"}`)
		if p = preview(t, privacyapp.ProposedRetentionChange{Action: "create", Spec: labelled}); p.Unknown != 3 || p.Affected != 0 || !p.EarliestDeleteBy.IsZero() {
			t.Fatalf("unknown selector history assumed: %+v", p)
		}
		// The catalog scan is bounded and reports truncation.
		if c, err := catalog.RetentionPreviewCatalog(ctx, 2); err != nil || len(c.Artifacts) != 2 || !c.Truncated {
			t.Fatalf("bounded scan: %d %v %v", len(c.Artifacts), c.Truncated, err)
		}
		if c, err := catalog.RetentionPreviewCatalog(ctx, 3); err != nil || len(c.Artifacts) != 3 || c.Truncated || len(c.Sources) != 1 || !c.Sources[0].Ready || c.Sources[0].Current == nil {
			t.Fatalf("complete scan: %+v %v", c, err)
		}
		if after := effective(t, s.a.RootID); len(after) != len(before) {
			t.Fatal("preview changed the catalog")
		} else {
			for k, v := range before {
				if after[k] != v {
					t.Fatal("preview changed a deadline", k)
				}
			}
		}

		// Apply a real shortening to one hour through acceptance, audit and
		// catch-up: the artifacts now carry a lifecycle decision.
		sourcePool := poolFor("retention_source_runtime", "synthetic-retention-source")
		defer sourcePool.Close()
		sources, err := postgres.NewRetentionSources(ctx, sourcePool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		catchupPool := poolFor("retention_catchup_runtime", "synthetic-retention-catchup")
		defer catchupPool.Close()
		worker, err := postgres.NewRetention(ctx, catchupPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		auditPool := poolFor("retention_source_audit_runtime", "synthetic-retention-source-audit")
		defer auditPool.Close()
		auditor, err := postgres.NewRetentionSources(ctx, auditPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := s.retention.checkpoint
		policy := checkpoint.Transition.List.Snapshot.Policies[0]
		journal, err := app.ResumeRetentionJournal(checkpoint.Transition.List)
		if err != nil {
			t.Fatal(err)
		}
		shorter := policy
		shorter.Policy.MaximumSeconds = 3600
		shorter.Policy.Revision.Generation = 2
		shorter.Policy.Revision.Digest = artifact.Digest{6}
		event := app.PolicyEvent{Type: "MODIFIED", ResourceVersion: "101", Policy: &shorter}
		if err = journal.Apply(event); err != nil {
			t.Fatal(err)
		}
		next, err := journal.HistoricalCheckpoint()
		if err != nil {
			t.Fatal(err)
		}
		fence := s.retention.fence
		if checkpoint, err = sources.AcceptRetention(ctx, app.RetentionTransition{ID: custodyID(), Fence: fence, List: next, Event: &event}); err != nil {
			t.Fatal(err)
		}
		if err = (app.RetentionAcceptancePublisher{Journal: auditor, Writer: &objectstore.RetentionAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).Publish(ctx, 64); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			page, err := worker.ReconcileRetentionPage(ctx, fence.Source, 16)
			if err != nil {
				t.Fatal(err)
			}
			if page.Idle {
				break
			}
		}
		s.retention.checkpoint = checkpoint
		s.retention.fence.Sequence = checkpoint.Record.Sequence
		bound := effective(t, s.a.RootID)
		for _, r := range registrations {
			if d := bound[r.Location.AttemptID]; !d[1].Equal(r.AnchorAt.Add(time.Hour)) {
				t.Fatal("catch-up did not bind the shorter deletion", d)
			}
		}
		// The source is not ready until the new lifecycle decisions are
		// audited, so the cluster is incomplete; the bound one-hour dates
		// are read from the decisions and a two-hour limit moves nothing.
		p = preview(t, privacyapp.ProposedRetentionChange{Action: "update", UID: "baseline", Spec: retentionPreviewSpec(7200)})
		if p.Complete() || len(p.Incomplete) != 1 || p.Incomplete[0].ClusterID != registrations[0].Location.ClusterID || p.Scanned != 3 || p.Unknown != 0 || p.Affected != 0 {
			t.Fatalf("bound lengthening: %+v", p)
		}
		if p = preview(t, privacyapp.ProposedRetentionChange{Action: "update", UID: "baseline", Spec: retentionPreviewSpec(600)}); p.Affected != 3 || !p.EarliestDeleteBy.Equal(anchor.Add(10*time.Minute)) {
			t.Fatalf("shortening after a bound decision: %+v", p)
		}
		// Unknown objects are reported, not evaluated.
		if p = preview(t, privacyapp.ProposedRetentionChange{Action: "delete", UID: "absent"}); len(p.NotEvaluated) != 1 || p.NotEvaluated[0].Reason != privacy.PreviewUnknownObject {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("retention-preview-scan-cost", func(t *testing.T) {
		n := 1000
		if v, err := strconv.Atoi(os.Getenv("ASSERVAT_RETENTION_PREVIEW_ARTIFACTS")); err == nil && v > 0 && v <= privacy.MaxRetentionPreviewArtifacts {
			n = v
		}
		s := create(t, int64(n))
		start := time.Now()
		n = len(admitRetentionPreviewContexts(t, ctx, s, n, 3500*time.Millisecond))
		catalog, err := postgres.NewRetentionSources(ctx, previewPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("admitted %d contexts in %s", n, time.Since(start))
		var rowBytes, expectationBytes, scopeBytes float64
		if err := admin.QueryRow(ctx, "SELECT avg(octet_length(c::text)+octet_length(a::text)),avg(octet_length(c.expectation_json)),avg(octet_length(c.scope_json)) FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id WHERE c.root_id=$1", s.a.RootID).Scan(&rowBytes, &expectationBytes, &scopeBytes); err != nil {
			t.Fatal(err)
		}
		t.Logf("row text %.0f bytes: expectation %.0f, scope %.0f", rowBytes, expectationBytes, scopeBytes)
		if _, err := catalog.RetentionPreviewCatalog(ctx, 1); err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		if _, err := catalog.RetentionPreviewCatalog(ctx, 1); err != nil {
			t.Fatal(err)
		}
		t.Logf("sources and one artifact: %s", time.Since(start))
		if err := s.retention.observe(ctx); err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		c, err := catalog.RetentionPreviewCatalog(ctx, privacy.MaxRetentionPreviewArtifacts)
		read := time.Since(start)
		if err != nil || len(c.Artifacts) != n || c.Truncated {
			t.Fatalf("%d %v %v", len(c.Artifacts), c.Truncated, err)
		}
		spec, err := decoder.DecodeRetentionPolicySpec(retentionPreviewSpec(600), true)
		if err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		p, err := privacy.PreviewRetention([]privacy.RetentionChange{{Action: "update", UID: "baseline", Policy: spec}}, c, time.Now().UTC())
		evaluate := time.Since(start)
		if err != nil || p.Affected != n {
			t.Fatalf("%+v %v", p, err)
		}
		t.Logf("retention preview over %d artifacts (%.0f bytes/row): catalog read %s, evaluation %s (%.1f µs/artifact read, %.1f µs/artifact evaluated)", n, rowBytes, read, evaluate, float64(read.Microseconds())/float64(n), float64(evaluate.Microseconds())/float64(n))
	})
}
