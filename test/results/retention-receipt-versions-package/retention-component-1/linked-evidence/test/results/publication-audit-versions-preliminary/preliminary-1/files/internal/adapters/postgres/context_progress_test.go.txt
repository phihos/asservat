package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgtype"
)

func progressFactsFixture(t *testing.T, stage string) custodydb.ReadContextProgressFactsRow {
	t.Helper()
	p := previewTestValue(t)
	now := p.CreatedAt
	scope, _ := json.Marshal(map[string]any{"executor": map[string]any{"issuer": p.Actor.Issuer, "subject": p.Actor.Subject, "clientID": p.Actor.ClientID, "identityType": p.Actor.Kind}})
	sd := sha256.Sum256(scope)
	r := artifact.Registration{Location: artifact.Location{ClusterID: p.Target.ClusterID, ArtifactID: p.ArtifactID, AttemptID: p.AttemptID}, StoreID: p.Storage.StoreID, AllocationID: p.Storage.AllocationID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: p.Deadline, ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(time.Hour + time.Minute)}
	e := artifact.ContextExpectation{NodeUID: p.RootID, NodeBootID: p.IssuerEpoch, Registration: r, CaseID: p.CaseID, OccurrenceID: p.OccurrenceID, PodUID: p.Target.PodUID, Namespace: p.Target.Namespace.Name, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, CollectorVersion: "test-1", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: sd, CaptureUID: p.CaptureID, ActionID: "pod-status", DataClass: "metadata", PurposeRef: p.Retention.PurposeRef, Audience: p.Audience, RequestedAgeSeconds: 3600, MaximumAgeSeconds: 7200, DeletionBudgetSeconds: 60, RetentionRules: p.Retention.Policies, TriggeredAt: now}
	if e.Validate() != nil {
		t.Fatal("invalid fixture expectation")
	}
	ej, _ := json.Marshal(e)
	pj, _ := json.Marshal(p.Pin)
	c := custodydb.ContextCapture{ID: id(p.CaptureID), RootID: id(p.RootID), RequestKey: make([]byte, 32), SubmissionDigest: digest("submission"), ScopeDigest: sd[:], ScopeJson: scope, ExpectationJson: ej, PodPinJson: pj, AttemptID: id(p.AttemptID), PermissionEpoch: id(p.IssuerEpoch), PermissionSequence: 1, IdentityPolicyUid: "identity", IdentityPolicyGeneration: 1, IdentityPolicyDigest: digest("policy"), CreatedAt: ts(now), Deadline: ts(p.Deadline), State: value.PendingAudit, ProgressRevision: 1}
	f := custodydb.ReadContextProgressFactsRow{ContextCapture: c, CustodyState: artifact.Reserved, RequestDigest: digest(normalized(r)), EffectiveExpiresAt: ts(r.ExpiresAt), EffectiveDeleteBy: ts(r.DeleteBy)}
	if stage == "pending" {
		return f
	}
	intent, err := captureIntent(c)
	if err != nil {
		t.Fatal(err)
	}
	c.State = value.IntentAudited
	c.IntentAcknowledgedAt = ts(now.Add(time.Second))
	c.IntentDigest = digest(intent)
	c.IntentObjectKey = pgtype.Text{String: audit.CaptureIntentKey(intent.RootID, intent.CaptureID), Valid: true}
	c.IntentObjectVersion = pgtype.Text{String: "synthetic-version", Valid: true}
	c.IntentObjectEtag = pgtype.Text{String: "synthetic-etag", Valid: true}
	c.IntentObjectBytes = pgtype.Int8{Int64: 128, Valid: true}
	c.IntentObjectSha256 = digest("synthetic-capture-audit")
	c.ProgressRevision++
	f.ContextCapture = c
	if stage == "audited" {
		return f
	}
	f.CustodyState = artifact.StoredUnpublished
	f.CopiesDigest = digest("synthetic-copies")
	f.ContextCapture.ProgressRevision++
	if stage == "stored" {
		return f
	}
	f.VerifiedCaptureID = c.ID
	f.VerifiedRootID = c.RootID
	f.VerifiedAt = ts(now.Add(2 * time.Second))
	f.ExpectationDigest = digest(e)
	f.VerifiedCopiesDigest = f.CopiesDigest
	f.VerifiedIntentDigest = c.IntentDigest
	f.AuthorityDigest = digest("authority")
	f.PermissionEpoch = c.PermissionEpoch
	f.PermissionSequence = pgtype.Int8{Int64: 1, Valid: true}
	f.ContextCapture.ProgressRevision++
	if stage == "verified" {
		return f
	}
	record, err := verificationRecord(c, custodydb.ContextVerification{CaptureID: c.ID, RootID: c.RootID, VerifiedAt: f.VerifiedAt, ExpectationDigest: f.ExpectationDigest, CopiesDigest: f.VerifiedCopiesDigest, IntentDigest: f.VerifiedIntentDigest, AuthorityDigest: f.AuthorityDigest, PermissionEpoch: f.PermissionEpoch, PermissionSequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.AuditAcknowledgedAt = ts(now.Add(3 * time.Second))
	f.AuditDigest = digest(record)
	f.ContextCapture.ProgressRevision++
	if stage == "verification-audited" {
		return f
	}
	f.CatalogArtifactID = id(p.ArtifactID)
	f.PublishedAt = ts(now.Add(4 * time.Second))
	f.ContextCapture.ProgressRevision++
	return f
}
func TestProgressProjectsOnlyDurableFacts(t *testing.T) {
	for _, tc := range []struct{ stage, phase, reason string }{{"pending", "Pending", "IntentAuditPending"}, {"audited", "Pending", "DispatchUnconfirmed"}, {"stored", "Finalizing", "VerificationPending"}, {"verified", "Finalizing", "VerificationAuditPending"}, {"verification-audited", "Finalizing", "PublicationPending"}, {"published", "Succeeded", "Published"}} {
		t.Run(tc.stage, func(t *testing.T) {
			f := progressFactsFixture(t, tc.stage)
			got, err := progressFacts(f)
			if err != nil || got.Phase != tc.phase || got.ReasonCode != tc.reason || got.ActionPhase != tc.phase {
				t.Fatal(got, err)
			}
			f.ContextCapture.DeadlineObservedAt = ts(f.ContextCapture.Deadline.Time.Add(time.Second))
			f.ContextCapture.ProgressRevision++
			got, err = progressFacts(f)
			want := "Indeterminate"
			if tc.stage == "published" {
				want = "Succeeded"
			}
			if err != nil || got.Phase != want {
				t.Fatal("deadline overwrote durable outcome or invented timeout", got, err)
			}
		})
	}
}
func TestProgressRejectsIncompletePublicationOrCorruptIdentity(t *testing.T) {
	for name, change := range map[string]func(*custodydb.ReadContextProgressFactsRow){
		"revision-overflow": func(f *custodydb.ReadContextProgressFactsRow) {
			f.ContextCapture.ProgressRevision = value.MaxProgressRevision + 1
		},
		"registration": func(f *custodydb.ReadContextProgressFactsRow) { f.RequestDigest = digest("other") },
		"scope":        func(f *custodydb.ReadContextProgressFactsRow) { f.ContextCapture.ScopeJson = []byte(`{}`) },
		"intent-audit": func(f *custodydb.ReadContextProgressFactsRow) {
			f.ContextCapture.State = value.PendingAudit
			f.ContextCapture.IntentAcknowledgedAt = pgtype.Timestamptz{}
		},
		"verification":      func(f *custodydb.ReadContextProgressFactsRow) { f.VerifiedCaptureID = pgtype.UUID{} },
		"copies":            func(f *custodydb.ReadContextProgressFactsRow) { f.VerifiedCopiesDigest = digest("other") },
		"outcome-audit":     func(f *custodydb.ReadContextProgressFactsRow) { f.AuditAcknowledgedAt = pgtype.Timestamptz{} },
		"audit-digest":      func(f *custodydb.ReadContextProgressFactsRow) { f.AuditDigest = digest("other") },
		"wrong-artifact":    func(f *custodydb.ReadContextProgressFactsRow) { f.CatalogArtifactID = f.ContextCapture.ID },
		"early-publication": func(f *custodydb.ReadContextProgressFactsRow) { f.PublishedAt = f.ContextCapture.CreatedAt },
		"late-publication":  func(f *custodydb.ReadContextProgressFactsRow) { f.PublishedAt = f.ContextCapture.Deadline },
	} {
		t.Run(name, func(t *testing.T) {
			f := progressFactsFixture(t, "published")
			change(&f)
			if got, err := progressFacts(f); err == nil || got.CaptureID != "" {
				t.Fatal("unproven published progress", got, err)
			}
		})
	}
}

func TestContextMetadataDeadlineIsOriginalAndNotSerialized(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel()
	if got := contextMetadataDeadline(ctx, now.Add(3*time.Second), now.Add(2*time.Second)); !got.Equal(now.Add(time.Second)) {
		t.Fatal("original request deadline lost", got)
	}
	if got := contextMetadataDeadline(context.Background(), now.Add(3*time.Second), now.Add(100*time.Millisecond)); !got.Equal(now.Add(100 * time.Millisecond)) {
		t.Fatal("short permission deadline renewed", got)
	}
	if got := contextMetadataDeadline(context.Background(), time.Time{}, now.Add(time.Second)); !got.IsZero() {
		t.Fatal("missing authority accepted")
	}
	b, err := json.Marshal(value.Accepted{MetadataValidUntil: now})
	if err != nil || bytes.Contains(b, []byte("MetadataValidUntil")) {
		t.Fatal("response-only lease serialized", err)
	}
}
