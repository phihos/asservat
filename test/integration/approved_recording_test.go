package integration

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Uses real SQL with explicit synthetic bootstrap and a synthetic approved
// reviewer; independent reviewer/step-up qualification belongs to ADR-249.
func qualifyApprovedRecording(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T) captureAdmissionScenario) {
	t.Helper()
	t.Run("recording-approved-plan-after-preview-expiry", func(t *testing.T) {
		s := create(t)
		in := s.a.Plan.Input
		in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
		in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "packetAfter", Text: "2s"}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
		// A short preview makes expiry real without moving any database clock.
		oldDeadline := now.Add(time.Second)
		reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: in.Retention, Deadline: oldDeadline, NodeRecorder: true, RequireApproval: true}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesDigest(), RootID: s.a.RootID, InstallationID: s.a.Recovery.InstallationID, IssuerEpoch: s.a.Recovery.IssuerEpoch, CaptureID: in.CaptureID, CaseID: s.a.CaseID, OccurrenceID: s.a.OccurrenceID, ArtifactID: s.a.Registration.Location.ArtifactID, AttemptID: s.a.Registration.Location.AttemptID, Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
			Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Composition: &composition, RequestedSeconds: in.Retention.RequestedSeconds}, Target: in.Target.Request, Pin: in.Target.Pin,
			Storage: capture.ContextStorageSelection{StoreID: s.a.Registration.StoreID, AllocationID: s.a.Registration.AllocationID, PoolRevision: s.a.Registration.PoolRevision, AllocationRevision: s.a.Registration.AllocationRevision, BindingRevision: s.a.Storage.Revision}, Retention: capture.ContextRetentionReview{PurposeRef: in.Retention.PurposeRef, RequestedSeconds: in.Retention.RequestedSeconds, MaximumSeconds: in.Retention.MaximumSeconds, DeletionBudgetSeconds: in.Retention.DeletionBudgetSeconds, Policies: in.Retention.Policies}, Audience: s.a.Eligibility.DefaultAudience, CanonicalScope: reviewed.CanonicalScope, ScopeDigest: reviewed.ScopeDigest, CreatedAt: now, Deadline: oldDeadline}
		previewPool := poolFor("context_preview_runtime", "synthetic-context-preview")
		defer previewPool.Close()
		previews, err := postgres.NewContextPreviews(ctx, previewPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = previews.CreateContextPreview(ctx, p); err != nil {
			t.Fatal("persist preview", err)
		}
		role := narrowRole(t, ctx, admin, "approved_grant_", "synthetic-approved-grant", func(role string) []string {
			sql, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
			if !ok {
				t.Fatal("missing hub runtime grants")
			}
			return sql
		})
		grantPool := poolFor(role, "synthetic-approved-grant")
		defer grantPool.Close()
		grants, err := postgres.NewAccessGrants(ctx, grantPool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		g := authorization.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: reviewed.Actions[0].ID, Code: planvalue.ReasonRecordingApproval}}, Lifetime: time.Hour, Revision: 1}
		g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
		g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "approval", RequestDigest: sha256.Sum256([]byte("synthetic-request"))}, s.a.Recovery)
		if err != nil {
			t.Fatal("persist grant", err)
		}
		// Pending reviews retain the original blueprint and its quota slot.
		time.Sleep(time.Until(oldDeadline) + 10*time.Millisecond)
		if read, err := previews.ReadContextPreview(ctx, p.RootID, p.ID, p.Actor); err != nil || !read.Deadline.Equal(oldDeadline) {
			t.Fatal("expired review blueprint lost", err)
		}
		cleanup, err := postgres.NewContextPreviewCleanup(ctx, previewPool, p.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if count, err := cleanup.DeleteExpiredContextPreviews(ctx); err != nil || count != 0 {
			t.Fatal("pending review deleted", count, err)
		}
		approver := p.Actor
		approver.Subject = "synthetic-independent-reviewer"
		g, _, err = grants.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: approver, Reason: "synthetic reviewed recording", ACR: "gold", AuthTime: time.Now().Add(-time.Second), IdempotencyKey: "approve"}, s.a.Recovery)
		if err != nil {
			t.Fatal("decision", err)
		}
		acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
		in.Deadline = acceptedAt.Add(time.Minute)
		in.Recorder, err = planning.RecorderContextFromScope(composition, p.CanonicalScope)
		if err != nil {
			t.Fatal(err)
		}
		in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: in.Retention.RequestedSeconds, AnchorAt: acceptedAt}, acceptedAt)
		if err != nil {
			t.Fatal(err)
		}
		s.a.Plan, err = planning.CompileContext(in, acceptedAt)
		if err != nil || s.a.Plan.ScopeDigest != p.ScopeDigest {
			t.Fatal("frozen plan changed", err)
		}
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		r := &s.a.Registration
		r.AnchorAt, r.WriteUntil, r.ExpiresAt, r.DeleteBy = acceptedAt, in.Deadline, in.Retention.ExpiresAt, in.Retention.DeleteBy
		if r.WriteUntil.After(r.ExpiresAt) {
			r.WriteUntil = r.ExpiresAt
		}
		accepted, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a)
		if err != nil {
			t.Fatal("approved admission after preview expiry", err)
		}
		if accepted.ScopeDigest != p.ScopeDigest || accepted.CaptureID != p.CaptureID || !accepted.Deadline.Equal(in.Deadline) {
			t.Fatal("approval or execution identity changed")
		}
		// Current-grant lock blocks revocation until the effect transaction ends.
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var until *time.Time
		if err = tx.QueryRow(ctx, "SELECT lock_approved_context_grant($1,$2,$3,$4,$5,$6,$7)", p.RootID, p.ID, p.CaptureID, p.Actor.Issuer, p.Actor.Subject, p.Actor.ClientID, p.ScopeDigest[:]).Scan(&until); err != nil || until == nil {
			t.Fatal("lock approval", err)
		}
		done := make(chan error, 1)
		go func() {
			_, _, e := grants.RevokeGrant(ctx, authapp.GrantRevocationInput{GrantID: g.ID, Revoker: p.Actor, ExpectedRevision: g.Revision, IdempotencyKey: "revoke"}, s.a.Recovery)
			done <- e
		}()
		select {
		case e := <-done:
			t.Fatal("revocation crossed the effect lock", e)
		case <-time.After(40 * time.Millisecond):
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal("revocation", err)
		}
		if err = admin.QueryRow(ctx, "SELECT lock_approved_context_grant($1,$2,$3,$4,$5,$6,$7)", p.RootID, p.ID, p.CaptureID, p.Actor.Issuer, p.Actor.Subject, p.Actor.ClientID, p.ScopeDigest[:]).Scan(&until); err != nil || until != nil {
			t.Fatal("revoked grant usable", err)
		}
		// Historical accepted operation remains replayable; no new acquisition.
		again, err := s.s.AdmitReviewedContext(ctx, p.ID, s.a)
		if err != nil || !again.Replay || again.CaptureID != accepted.CaptureID || !again.Deadline.Equal(accepted.Deadline) {
			t.Fatal("historical replay changed", err)
		}
	})
}
