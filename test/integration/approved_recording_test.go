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
	t.Run("recording-composition-group", func(t *testing.T) {
		qualifyCompositionGroup(t, ctx, admin, poolFor, create(t))
	})
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

func reviewOf(r privacy.Resolution) capture.ContextRetentionReview {
	return capture.ContextRetentionReview{PurposeRef: r.PurposeRef, RequestedSeconds: r.RequestedSeconds, MaximumSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, Policies: r.Policies}
}

// ADR-276: a manual packet + syscall composition is one reviewed group whose
// approved parent grant admits both single recordings atomically; each child
// keeps its own scope, evidence type and retention, and replay is passive.
func qualifyCompositionGroup(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario) {
	in := s.a.Plan.Input
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	policies, err := s.retention.policies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	composition := planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{
		{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "packetAfter", Text: "2s"}}},
		{ID: "calls", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "syscalls", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "syscalls", Field: "syscallBefore", Text: "0s"}, {ActionID: "syscalls", Field: "syscallAfter", Text: "2s"}}},
	}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	parts, err := planning.SplitComposition(composition, recordingCompiler{})
	if err != nil || len(parts) != 2 {
		t.Fatal("split", err)
	}
	deadline := now.Add(time.Minute)
	group := &capture.CompositionGroupPreview{}
	plans := make([]planvalue.RecorderPlan, len(parts))
	evidence := make([]string, len(parts))
	var reasons []authorization.SensitiveReason
	for n, c := range parts {
		if evidence[n], err = planning.RecorderEvidenceType(c); err != nil {
			t.Fatal(err)
		}
		retention, err := privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence[n], AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		child := capture.CompositionGroupChild{CaptureID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID(), OccurrenceID: custodyID(), AssessmentID: custodyID(), Composition: c, Retention: reviewOf(retention)}
		plans[n], err = planning.CompileRecorder(planvalue.RecorderInput{CaptureID: child.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: retention, Deadline: deadline, NodeRecorder: true, RequireApproval: true}, recordingCompiler{}, now)
		if err != nil || plans[n].Approval == nil {
			t.Fatal("compile child", n, err)
		}
		child.ActionID, child.CanonicalScope, child.ScopeDigest = plans[n].Actions[0].ID, plans[n].CanonicalScope, plans[n].ScopeDigest
		group.Children = append(group.Children, child)
		reasons = append(reasons, plans[n].Approval.Reasons...)
	}
	parentID := custodyID()
	scope, digest, err := planning.CompileRecorderGroup(parentID, plans)
	if err != nil {
		t.Fatal("group scope", err)
	}
	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesDigest(), RootID: s.a.RootID, InstallationID: s.a.Recovery.InstallationID, IssuerEpoch: s.a.Recovery.IssuerEpoch, CaptureID: parentID, CaseID: s.a.CaseID, OccurrenceID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID(), Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
		Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Composition: &composition}, Target: in.Target.Request, Pin: in.Target.Pin,
		Storage: capture.ContextStorageSelection{StoreID: s.a.Registration.StoreID, AllocationID: s.a.Registration.AllocationID, PoolRevision: s.a.Registration.PoolRevision, AllocationRevision: s.a.Registration.AllocationRevision, BindingRevision: s.a.Storage.Revision}, Retention: group.Children[0].Retention, Audience: s.a.Eligibility.DefaultAudience, CanonicalScope: scope, ScopeDigest: digest, CreatedAt: now, Deadline: deadline, CompositionGroup: group}
	if !captureapp.ValidContextPreview(p) {
		t.Fatal("invalid group preview")
	}
	previewPool := poolFor("context_preview_runtime", "synthetic-context-preview")
	defer previewPool.Close()
	previews, err := postgres.NewContextPreviews(ctx, previewPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateContextPreview(ctx, p); err != nil {
		t.Fatal("persist group preview", err)
	}
	if read, err := previews.ReadContextPreview(ctx, p.RootID, p.ID, p.Actor); err != nil || read.CompositionGroup == nil || len(read.CompositionGroup.Children) != 2 {
		t.Fatal("read group preview", err)
	}
	role := narrowRole(t, ctx, admin, "group_grant_", "synthetic-group-grant", func(role string) []string {
		sql, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing hub runtime grants")
		}
		return sql
	})
	grantPool := poolFor(role, "synthetic-group-grant")
	defer grantPool.Close()
	grants, err := postgres.NewAccessGrants(ctx, grantPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g := authorization.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: "extract", Reasons: reasons, Lifetime: time.Hour, Revision: 1}
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "group-approval", RequestDigest: sha256.Sum256([]byte("synthetic-group-request"))}, s.a.Recovery)
	if err != nil {
		t.Fatal("persist grant", err)
	}
	approver := p.Actor
	approver.Subject = "synthetic-independent-reviewer"
	if g, _, err = grants.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: approver, Reason: "synthetic reviewed group", ACR: "gold", AuthTime: time.Now().Add(-time.Second), IdempotencyKey: "approve"}, s.a.Recovery); err != nil {
		t.Fatal("decision", err)
	}
	acceptedAt := time.Now().UTC().Truncate(time.Microsecond)
	p.CreatedAt, p.Deadline = acceptedAt, acceptedAt.Add(time.Minute)
	request := capture.RecordingSaveGroupAdmission{Preview: p, RootID: s.a.RootID, IdempotencyKey: "composition-group", SubmissionDigest: captureapp.ContextRequestDigest(p.ID), Recovery: s.a.Recovery}
	for n, c := range group.Children {
		ci := in
		ci.CaptureID, ci.Deadline = c.CaptureID, p.Deadline
		if ci.Recorder, err = planning.RecorderContextFromScope(c.Composition, c.CanonicalScope); err != nil {
			t.Fatal(err)
		}
		if ci.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence[n], AnchorAt: acceptedAt}, acceptedAt); err != nil {
			t.Fatal(err)
		}
		a := s.a
		a.IdempotencyKey, a.SubmissionDigest, a.OccurrenceID = request.IdempotencyKey, request.SubmissionDigest, c.OccurrenceID
		if a.Plan, err = planning.CompileContext(ci, acceptedAt); err != nil || a.Plan.ScopeDigest != c.ScopeDigest {
			t.Fatal("frozen child plan changed", n, err)
		}
		a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = c.ArtifactID, c.AttemptID
		a.Registration.AnchorAt, a.Registration.WriteUntil, a.Registration.ExpiresAt, a.Registration.DeleteBy = acceptedAt, p.Deadline, ci.Retention.ExpiresAt, ci.Retention.DeleteBy
		if a.Registration.WriteUntil.After(a.Registration.ExpiresAt) {
			a.Registration.WriteUntil = a.Registration.ExpiresAt
		}
		request.Children = append(request.Children, a)
	}
	accepted, err := s.s.AdmitRecordingCompositionGroup(ctx, request)
	if err != nil {
		t.Fatal("composition group admission", err)
	}
	if accepted.Group == nil || len(accepted.Group.Children) != 2 || accepted.CaptureID != parentID || accepted.ScopeDigest != digest || accepted.Replay {
		t.Fatalf("accepted group %+v", accepted)
	}
	for n, child := range accepted.Group.Children {
		b := child.Expectation.CompositionGroup
		if child.CaptureID != group.Children[n].CaptureID || child.ScopeDigest != group.Children[n].ScopeDigest || b == nil || b.ParentCaptureID != parentID || b.ChildIndex != n || b.ChildCount != 2 || child.Expectation.Recording == nil || !child.CreatedAt.Equal(accepted.CreatedAt) {
			t.Fatalf("child %d %+v", n, child.Expectation.CompositionGroup)
		}
	}
	again, err := s.s.AdmitRecordingCompositionGroup(ctx, request)
	if err != nil || !again.Replay || again.CaptureID != parentID || len(again.Group.Children) != 2 {
		t.Fatal("group replay", err)
	}
	// The grant binds the parent: revoking it closes new admissions.
	other := request
	other.IdempotencyKey = "another-key"
	if _, _, err = grants.RevokeGrant(ctx, authapp.GrantRevocationInput{GrantID: g.ID, Revoker: p.Actor, ExpectedRevision: g.Revision, IdempotencyKey: "revoke"}, s.a.Recovery); err != nil {
		t.Fatal("revoke", err)
	}
	if _, err = s.s.AdmitRecordingCompositionGroup(ctx, other); err == nil {
		t.Fatal("a second admission under a revoked grant")
	}
}
