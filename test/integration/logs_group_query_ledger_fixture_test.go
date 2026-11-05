package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/planning"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// One pristine managed root, actual compiled roles and immutable parent/child
// scopes. Payloads, target process and transport joins remain synthetic. This
// fixture is independent of installed Kubernetes capture and browser proof.
func TestLogsMixedGroupQueryLifecycleWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyLogsMixedGroup, false, false, false, false, false, false, true, true)
	})
}

func logsMixedGroupComposition() planvalue.ProfileComposition {
	return planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{
		{ID: "logs", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "logs", Field: "actionMaxBytes", Number: artifact.LogNativeLimit}}},
		{ID: "net", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "sample", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "sample", Field: "packetBefore", Text: "0s"}, {ActionID: "sample", Field: "packetAfter", Text: "1s"}, {ActionID: "sample", Field: "actionTimeout", Text: "10s"}}},
		{ID: "calls", Profile: planvalue.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}, Edits: []planvalue.ProfileEdit{{ActionID: "syscalls", Field: "actionExecutionMode", Text: "onTrigger"}, {ActionID: "syscalls", Field: "syscallBefore", Text: "0s"}, {ActionID: "syscalls", Field: "syscallAfter", Text: "1s"}, {ActionID: "syscalls", Field: "actionTimeout", Text: "10s"}}},
	}, MaxTotalBytes: artifact.LogNativeLimit + 2*(16<<20), MaxDuration: "10s"}
}

type logsMixedAccepted struct {
	scenario  captureAdmissionScenario
	parent    capture.Accepted
	request   capture.RecordingSaveGroupAdmission
	grant     authorization.Grant
	grants    *postgres.AccessGrants
	execution *postgres.APIContextExecutions
	children  []captureAdmissionScenario
	logsIndex int
}

func admitLogsMixedGroup(t *testing.T, f *queryLedgerFixture) logsMixedAccepted {
	t.Helper()
	ctx, b := f.base.ctx, f.base
	// The scalar setup already owns these live accepted sources. Starting a
	// second retention producer here would attempt to replace its live epoch.
	// Reuse the same source/store and refresh facts for this separate request.
	s := f.scenario
	publisher := logsExistingCapturePublisher(t, f)
	f.refresh(t)
	observed := time.Now().UTC().Truncate(time.Microsecond)
	s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = observed, observed.Add(5*time.Second), nil
	if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
		t.Fatal("mixed current existing permission source", err)
	}
	in := s.a.Plan.Input
	currentPermissions, err := s.p.Permissions(ctx, in.Target.Target())
	if err != nil {
		t.Fatal("mixed current permission projection", err)
	}
	currentIdentity := s.a.Eligibility.VerifiedIdentity
	currentIdentity.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	currentIdentity.ValidUntil = currentIdentity.VerifiedAt.Add(5 * time.Second)
	s.a.Eligibility = authorization.ContextEligibility(currentIdentity, currentPermissions, in.Target.Target(), time.Now())
	if !s.a.Eligibility.Eligible {
		t.Fatal("mixed independent current identity", s.a.Eligibility.Reason)
	}
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.a.Recovery.InstallationID || recovery.IssuerEpoch != s.a.Recovery.IssuerEpoch || recovery.Revision != s.a.Recovery.Revision {
		t.Fatal("mixed original accepted recovery changed", err)
	}
	s.a.Recovery = recovery
	storage, err := postgres.NewContextStorageReader(ctx, b.roles["hub-runtime"], s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := storage.ContextStorage(ctx, in.Target.Target())
	if err != nil || selected.Selection.StoreID != s.a.Registration.StoreID || selected.Selection.AllocationID != s.a.Registration.AllocationID || selected.Selection.PoolRevision != s.a.Registration.PoolRevision || selected.Selection.AllocationRevision != s.a.Registration.AllocationRevision || selected.Binding.RootID != s.a.RootID || selected.Binding.Revision != s.a.Storage.Revision || selected.Binding.ClusterID != s.a.Storage.ClusterID || selected.Binding.NamespaceUID != s.a.Storage.NamespaceUID || selected.Binding.WorkloadUID != s.a.Storage.WorkloadUID {
		t.Fatal("mixed original accepted storage changed", err)
	}
	s.a.Storage = selected.Binding
	policies, err := s.retention.policies(ctx)
	if err != nil {
		t.Fatal("mixed existing retained source", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	// Target and capability observations are independently controlled fixture
	// inputs, with the same pinned Pod and qualification as the scalar source.
	in.Target.ObservedAt, in.Target.FreshUntil = now, now.Add(5*time.Second)
	in.Capability.ObservedAt, in.Capability.FreshUntil = now, now.Add(5*time.Second)
	s.a.CaseID = custodyID()
	in.CaseID = s.a.CaseID
	deadline := now.Add(time.Minute)
	composition := logsMixedGroupComposition()
	parts, err := planning.SplitComposition(composition, recordingCompiler{})
	if err != nil || len(parts) != 3 {
		t.Fatal("split actual mixed composition", err)
	}
	group := &capture.CompositionGroupPreview{}
	plans := make([]planvalue.RecorderPlan, len(parts))
	types := make([]string, len(parts))
	var reasons []authorization.SensitiveReason
	var reviewedActions []planvalue.RecorderAction
	logsIndex := -1
	for n, c := range parts {
		types[n], err = planning.RecorderEvidenceType(c)
		if err != nil {
			t.Fatal(err)
		}
		retention, err := privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: types[n], AnchorAt: now}, now)
		if err != nil {
			t.Fatal(err)
		}
		child := capture.CompositionGroupChild{CaptureID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID(), OccurrenceID: custodyID(), AssessmentID: custodyID(), Composition: c, Retention: reviewOf(retention)}
		plans[n], err = planning.CompileRecorder(planvalue.RecorderInput{CaptureID: child.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: retention, Deadline: deadline, NodeRecorder: true, RequireApproval: true}, recordingCompiler{}, now)
		if err != nil || len(plans[n].Actions) != 1 || plans[n].Approval == nil {
			t.Fatal("compiled mixed child", n, err)
		}
		child.ActionID, child.CanonicalScope, child.ScopeDigest = plans[n].Actions[0].ID, plans[n].CanonicalScope, plans[n].ScopeDigest
		group.Children = append(group.Children, child)
		reasons = append(reasons, plans[n].Approval.Reasons...)
		reviewedActions = append(reviewedActions, plans[n].Actions...)
		if types[n] == "logs" {
			logsIndex = n
		}
	}
	if logsIndex < 0 {
		t.Fatal("missing typed logs child")
	}
	parentID := custodyID()
	scope, digest, err := planning.CompileRecorderGroup(parentID, plans)
	if err != nil {
		t.Fatal("actual mixed group scope", err)
	}
	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planning.RecorderAssessmentRulesFor(reviewedActions), RootID: s.a.RootID, InstallationID: s.a.Recovery.InstallationID, IssuerEpoch: s.a.Recovery.IssuerEpoch, CaptureID: parentID, CaseID: s.a.CaseID, OccurrenceID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID(), Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
		Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Composition: &composition}, Target: in.Target.Request, Pin: in.Target.Pin,
		Storage: capture.ContextStorageSelection{StoreID: s.a.Registration.StoreID, AllocationID: s.a.Registration.AllocationID, PoolRevision: s.a.Registration.PoolRevision, AllocationRevision: s.a.Registration.AllocationRevision, BindingRevision: s.a.Storage.Revision}, Retention: group.Children[0].Retention, Audience: s.a.Eligibility.DefaultAudience, CanonicalScope: scope, ScopeDigest: digest, CreatedAt: now, Deadline: deadline, CompositionGroup: group}
	if !captureapp.ValidContextPreview(p) {
		t.Fatal("invalid real mixed preview")
	}
	previews, err := postgres.NewContextPreviews(ctx, b.roles["hub-runtime"], p.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateContextPreview(ctx, p); err != nil {
		t.Fatal("persist mixed preview under compiled hub role", err)
	}
	grants, err := postgres.NewAccessGrants(ctx, b.roles["hub-runtime"], p.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g := authorization.Grant{ID: custodyID(), RootID: p.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: "raw", Reasons: reasons, Lifetime: time.Hour, Revision: 1}
	g.ResultAccess = &authorization.ResultAccess{ActionIDs: []string{group.Children[logsIndex].ActionID}, Operations: []string{authorization.GrantDownloadOperation, authorization.GrantLogQueryOperation}, ClientIDs: []string{p.Actor.ClientID}, MaxArtifacts: 1, MaxBytes: 2 * query.ContextResultBytes, MaxOperations: 2, NotAfter: now.Add(time.Hour)}
	g.ResultAccessDigest = authapp.ResultAccessDigest(g.CaptureID, g.ExecutionDigest, *g.ResultAccess)
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "mixed-logs-review", RequestDigest: sha256.Sum256([]byte("synthetic-reviewed-mixed-logs"))}, s.a.Recovery)
	if err != nil {
		t.Fatal("compiled role parent review", err)
	}
	reviewer := p.Actor
	reviewer.Subject = "synthetic-independent-mixed-reviewer"
	g, _, err = grants.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: g.ID, Approve: true, Approver: reviewer, Reason: "synthetic reviewed mixed logs and metadata", ACR: "gold", AuthTime: time.Now().Add(-time.Second), IdempotencyKey: "approve-mixed-logs"}, s.a.Recovery)
	if err != nil {
		t.Fatal("independent parent decision", err)
	}
	// Match C18's ADR252 approved-acceptance branch. Protected preview bytes
	// and every child scope stay unchanged; only the approved acceptance time
	// is selected now, capped by the already approved parent's original end.
	for _, child := range group.Children {
		if !planning.RecorderApprovedAcceptance(child.CanonicalScope) {
			t.Fatal("mixed child not approved-acceptance timing")
		}
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	p.CreatedAt, p.Deadline = at, identity.Earlier(at.Add(time.Minute), g.ExpiresAt)
	request := capture.RecordingSaveGroupAdmission{Preview: p, RootID: p.RootID, IdempotencyKey: "mixed-logs-admission", SubmissionDigest: captureapp.ContextRequestDigest(p.ID), Recovery: s.a.Recovery}
	scenarios := make([]captureAdmissionScenario, len(parts))
	for n, c := range group.Children {
		ci := in
		ci.CaptureID, ci.Deadline = c.CaptureID, p.Deadline
		ci.Recorder = nil
		ci.Profile = nil
		ci.Logs = nil
		if n == logsIndex {
			ci.Logs = &planvalue.LogsContext{Composition: c.Composition, RequireApproval: true}
		} else {
			ci.Recorder, err = planning.RecorderContextFromScope(c.Composition, c.CanonicalScope)
			if err != nil {
				t.Fatal(err)
			}
		}
		ci.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: types[n], AnchorAt: at}, at)
		if err != nil {
			t.Fatal(err)
		}
		a := s.a
		a.IdempotencyKey, a.SubmissionDigest, a.OccurrenceID = request.IdempotencyKey, request.SubmissionDigest, c.OccurrenceID
		a.Plan, err = planning.CompileContext(ci, at)
		if err != nil || a.Plan.ScopeDigest != c.ScopeDigest {
			t.Fatal("frozen mixed child plan changed", n, err)
		}
		a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = c.ArtifactID, c.AttemptID
		a.Registration.NativeLimit = artifact.RecordingNativeLimit
		if n == logsIndex {
			a.Registration.NativeLimit = artifact.LogNativeLimit
		}
		a.Registration.AnchorAt, a.Registration.WriteUntil, a.Registration.ExpiresAt, a.Registration.DeleteBy = at, p.Deadline, ci.Retention.ExpiresAt, ci.Retention.DeleteBy
		if a.Registration.WriteUntil.After(a.Registration.ExpiresAt) {
			a.Registration.WriteUntil = a.Registration.ExpiresAt
		}
		request.Children = append(request.Children, a)
		scenarios[n] = s
		scenarios[n].a = a
	}
	accepted, err := s.s.AdmitRecordingCompositionGroup(ctx, request)
	if err != nil {
		t.Fatal("compiled role mixed group admission", err)
	}
	if accepted.Group == nil || len(accepted.Group.Children) != 3 || accepted.CaptureID != parentID || accepted.ScopeDigest != digest {
		t.Fatal("parent/children relabeled", accepted)
	}
	for n, child := range accepted.Group.Children {
		binding := child.Expectation.CompositionGroup
		if child.CaptureID != group.Children[n].CaptureID || child.ScopeDigest != group.Children[n].ScopeDigest || binding == nil || binding.ParentCaptureID != parentID || binding.ChildIndex != n || binding.ChildCount != 3 {
			t.Fatal("immutable group binding changed", n)
		}
		if n == logsIndex {
			if child.Expectation.Logs == nil || child.Expectation.Recording != nil || child.Expectation.NativeType != artifact.LogsArtifact {
				t.Fatal("logs child invented as recorder")
			}
		} else if child.Expectation.Logs != nil || child.Expectation.Recording == nil || child.Expectation.DataClass != "metadata" {
			t.Fatal("metadata source relabeled raw/logs")
		}
	}
	var chargedBefore, chargedAfter int64
	if err = b.admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", s.a.Registration.AllocationID).Scan(&chargedBefore); err != nil {
		t.Fatal(err)
	}
	replay, err := s.s.AdmitRecordingCompositionGroup(ctx, request)
	if err != nil || !replay.Replay || replay.CaptureID != parentID || !replay.Deadline.Equal(accepted.Deadline) {
		t.Fatal("mixed admission replay changed original", err)
	}
	var members int
	if err = b.admin.QueryRow(ctx, "SELECT count(*) FROM context_capture WHERE group_id=$1", parentID).Scan(&members); err != nil || members != 3 {
		t.Fatal("replay duplicated/missed accepted children", members, err)
	}
	if err = b.admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", s.a.Registration.AllocationID).Scan(&chargedAfter); err != nil || chargedBefore != chargedAfter {
		t.Fatal("passive group replay recharged storage", chargedBefore, chargedAfter, err)
	}
	if _, err = publisher.AcknowledgedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("actual parent capture intent", err)
	}
	execSQL, err := postgres.NewAPIContextExecutions(ctx, b.roles["hub-runtime"], p.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	return logsMixedAccepted{scenario: s, parent: accepted, request: request, grant: g, grants: grants, execution: execSQL, children: scenarios, logsIndex: logsIndex}
}

func qualifyLogsMixedGroup(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	mixed := admitLogsMixedGroup(t, f)
	// The initial scalar is managed setup, not a sibling or evidence of grouping.
	standalone := f.published
	logsChild := mixed.parent.Group.Children[mixed.logsIndex]
	scenario, published := publishQueryLedgerLogs(t, f.base, mixed.children[mixed.logsIndex], logsChild, mixed.execution)
	f.scenario, f.published, f.initialResultGrantID = scenario, published, mixed.grant.ID
	assertMixedLogGrantAssociation(t, f, mixed, standalone)
	assertMixedLogProgress(t, f, mixed, "Pending")
	for n, child := range mixed.parent.Group.Children {
		if n == mixed.logsIndex {
			continue
		}
		started, refresh := startQueryLedgerProfile(t, f.base, mixed.children[n], child, mixed.execution)
		check := refresh()
		started.Phase = "captureFailed"
		started.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
		if !started.Valid() {
			t.Fatal("synthetic failed metadata outcome malformed")
		}
		if _, err := mixed.execution.RecordAPIOutcome(f.base.ctx, started, check.Process); err != nil {
			t.Fatal("record exact failed sibling", err)
		}
	}
	assertMixedLogProgress(t, f, mixed, "Partial")
	// Existing real compiled query/key/ciphertext/audit lifecycle performs both
	// reads, the same-key pending replay and no extra raw grant creation.
	qualifyPacketQueryManagedLifecycle(t, f)
}

func assertMixedLogGrantAssociation(t *testing.T, f *queryLedgerFixture, m logsMixedAccepted, standalone artifact.PublishedContext) {
	t.Helper()
	ctx := f.base.ctx
	e := f.published.Expectation
	output := authorization.VerifiedOutput{ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ActionID: e.ActionID, ArtifactDigest: evidence.ContextCopiesDigest(f.published.Copies), ExecutionDigest: e.PlanDigest, Target: authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}}
	group := authorization.GrantOutputGroup{RootID: m.grant.RootID, ParentCaptureID: m.parent.CaptureID, CaptureID: e.CaptureUID, ArtifactID: output.ArtifactID, ActionID: e.ActionID, ParentExecutionDigest: m.parent.ScopeDigest, ExecutionDigest: e.PlanDigest, ArtifactDigest: output.ArtifactDigest, ChildIndex: m.logsIndex, ChildCount: 3}
	if !group.Matches(m.grant, output) {
		t.Fatal("test association not valid")
	}
	recovery, err := m.scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var v string
		if err := f.base.admin.QueryRow(ctx, `SELECT jsonb_build_object('children',(SELECT count(*) FROM access_grant_child WHERE parent_id=$1),'spend',(SELECT jsonb_build_array(artifacts_spent,bytes_spent,operations_spent) FROM access_grant WHERE id=$1))::text`, m.grant.ID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := snapshot()
	for _, kind := range []string{"unrelated-parent", "mutated-child-scope", "stale-parent-scope", "mutated-output-scope", "mutated-artifact-version", "wrong-ordinal", "standalone-output"} {
		t.Run(kind, func(t *testing.T) {
			g, o := group, output
			switch kind {
			case "unrelated-parent":
				g.ParentCaptureID = custodyID()
			case "mutated-child-scope":
				g.ExecutionDigest = artifact.Digest{99}
			case "stale-parent-scope":
				g.ParentExecutionDigest = artifact.Digest{98}
			case "mutated-output-scope":
				o.ExecutionDigest = artifact.Digest{97}
			case "mutated-artifact-version":
				o.ArtifactDigest = artifact.Digest{96}
			case "wrong-ordinal":
				g.ChildIndex = (g.ChildIndex + 1) % 3
			case "standalone-output":
				o.CaptureID = standalone.Expectation.CaptureUID
				o.ArtifactID = standalone.Expectation.Registration.Location.ArtifactID
				o.ArtifactDigest = evidence.ContextCopiesDigest(standalone.Copies)
				o.ExecutionDigest = standalone.Expectation.PlanDigest
			}
			_, _, err := m.grants.MaterializeGrantChild(ctx, authapp.GrantChildRequest{ChildID: custodyID(), ParentID: m.grant.ID, ClientID: m.grant.Requester.ClientID, Output: o, Group: &g}, recovery)
			if !errors.Is(err, authorization.ErrGrantScope) {
				t.Fatal("unassociated output materialized", kind, err)
			}
			if snapshot() != before {
				t.Fatal("denied association charged a child/use")
			}
		})
	}
	child, replay, err := m.grants.MaterializeGrantChild(ctx, authapp.GrantChildRequest{ChildID: custodyID(), ParentID: m.grant.ID, ClientID: m.grant.Requester.ClientID, Output: output, Group: &group}, recovery)
	if err != nil || replay || child.Group == nil || *child.Group != group || child.Output != output {
		t.Fatal("exact child was relabeled or not materialized", err)
	}
	again, replay, err := m.grants.MaterializeGrantChild(ctx, authapp.GrantChildRequest{ChildID: custodyID(), ParentID: m.grant.ID, ClientID: m.grant.Requester.ClientID, Output: output, Group: &group}, recovery)
	if err != nil || !replay || again.ID != child.ID {
		t.Fatal("exact materialization replay", err)
	}
	after := snapshot()
	bad := group
	bad.ChildIndex = (bad.ChildIndex + 1) % 3
	if _, _, err = m.grants.MaterializeGrantChild(ctx, authapp.GrantChildRequest{ChildID: custodyID(), ParentID: m.grant.ID, ClientID: m.grant.Requester.ClientID, Output: output, Group: &bad}, recovery); !errors.Is(err, authorization.ErrGrantScope) || snapshot() != after {
		t.Fatal("stale replay assertion accepted/charged", err)
	}
}

func assertMixedLogProgress(t *testing.T, f *queryLedgerFixture, m logsMixedAccepted, want string) {
	t.Helper()
	ctx := f.base.ctx
	f.refresh(t)
	recovery, err := m.scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	human := m.scenario.a.Eligibility.VerifiedIdentity
	human.Scopes = append(slices.Clone(human.Scopes), "evidence:read")
	human.VerifiedAt, human.ValidUntil = now, now.Add(5*time.Second)
	reader, err := postgres.NewContextProgressReads(ctx, f.base.roles["hub-runtime"], m.grant.RootID, m.scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reader.ReadContextProgress(ctx, capture.ProgressQuery{RootID: m.grant.RootID, CaptureID: m.parent.CaptureID, Identity: human, Recovery: recovery})
	if err != nil || p.Phase != want || len(p.Actions) != 3 || p.CanCancel || p.Target.PodUID != m.parent.Group.Children[0].Expectation.PodUID || p.CandidateArtifactID != "" {
		t.Fatal("mixed progress erased child/fabricated parent artifact/Stop", want, p, err)
	}
	n := map[string]string{}
	for _, a := range p.Actions {
		n[a.InstanceID] = a.Phase
	}
	if n[m.parent.Group.Children[m.logsIndex].CaptureID] != "Succeeded" {
		t.Fatal("verified logs child not independently successful", n)
	}
	check := capture.CancellationCheck{RootID: m.grant.RootID, Identity: human, Recovery: recovery, CheckedAt: now, ValidUntil: identity.Earlier(human.ValidUntil, recovery.FreshUntil), Request: capture.CancellationRequest{CaptureID: m.parent.CaptureID, ExpectedRevision: p.Revision, IdempotencyKey: "no-composition-stop"}}
	if _, err = m.execution.RequestCaptureCancellation(ctx, check); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("composition parent Stop gained authority", err)
	}
	t.Logf("mixed managed logs+packet+syscall metadata progress=%s, successful logs child retained, no parent artifact/Stop", p.Phase)
}

// Validate the actual recipe expansion before spending a managed fixture. The
// recorder recipe ceilings are16MiB each; their existing native framing cap is
// independently8MiB. These configured limits must not be conflated.
func TestLogsMixedGroupCompositionClosedFamilies(t *testing.T) {
	parts, err := planning.SplitComposition(logsMixedGroupComposition(), recordingCompiler{})
	if err != nil || len(parts) != 3 {
		t.Fatal("mixed recipe expansion", err)
	}
	kinds := map[string]bool{}
	for _, part := range parts {
		kind, err := planning.RecorderEvidenceType(part)
		if err != nil || kinds[kind] {
			t.Fatal("wrong or repeated source family", kind, err)
		}
		kinds[kind] = true
	}
	if !kinds["logs"] || !kinds["packetCapture"] || !kinds["syscallTrace"] {
		t.Fatal("missing actual typed source family", kinds)
	}
}
