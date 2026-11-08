package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

const manualArgumentHubRolePurpose = "hub-runtime"
const manualArgumentAdmissionRolePurpose = "capture-admit"

func TestInstalledManualArgumentsFixtureRolePurposes(t *testing.T) {
	for _, purpose := range []string{manualArgumentHubRolePurpose, manualArgumentAdmissionRolePurpose} {
		if grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, "synthetic_role"); !ok || len(grants) == 0 {
			t.Errorf("fixture requests unsupported installed role %q", purpose)
		}
	}
}

// These are direct writes that remain excluded from the installed hub union;
// admission and the definer spend function retain their narrower effects.
func TestInstalledManualArgumentsFixtureMutationProbes(t *testing.T) {
	grants, ok := postgres.PublicRuntimeRoleGrantSQL(manualArgumentHubRolePurpose, "synthetic_role")
	if !ok {
		t.Fatal("missing installed hub role")
	}
	for _, probe := range []struct{ table, column string }{{"policy_observation_session", "event_credit"}, {"adhoc_observation_spend", "spent"}, {"context_capture", "expectation_json"}} {
		table := " ON TABLE \"public\".\"" + probe.table + "\" TO "
		for _, grant := range grants {
			if strings.Contains(grant, table) && (strings.HasPrefix(grant, "GRANT UPDATE ON ") || strings.HasPrefix(grant, "GRANT UPDATE(\""+probe.column+"\") ON ")) {
				t.Fatalf("fixture denial contradicts installed grant: %s", grant)
			}
		}
	}
}

// Recompile exactly as the runner does after separately resolving current
// catalog facts. This fixture supplies synthetic observations, not SQL authority.
func manualArgumentFixtureRecompile(in planvalue.ContextInput, recording *artifact.Recording, resolved []planvalue.CatalogProfile, now time.Time) (planvalue.ContextPlan, error) {
	var err error
	in.Recorder, err = planning.RecorderContextFor(recording)
	if err != nil {
		return planvalue.ContextPlan{}, err
	}
	in.Recorder.Composition.Resolved = resolved
	return planning.CompileContext(in, now)
}

func TestInstalledManualArgumentsFixtureRecompilesOriginalScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := policyRecorderOfflineAdmission(t, now)
	in := a.Plan.Input
	in.Executor = identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human}
	in.Retention.EvidenceType = "syscallTrace"
	in.Deadline = now.Add(time.Minute)
	composition := manualArgumentSQLComposition(t, in.Target)
	reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: true}, installedArgumentsCompiler{}, now)
	if err != nil {
		t.Fatal("fixture initial review", err)
	}
	in.Recorder, err = planning.RecorderContextFromScope(composition, reviewed.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := planning.CompileContext(in, now)
	if err != nil || accepted.ScopeDigest != reviewed.ScopeDigest {
		t.Fatal("fixture admission plan", err)
	}
	recording, _, err := planning.RecordingForContext(accepted)
	if err != nil {
		t.Fatal(err)
	}
	fresh := now.Add(time.Millisecond)
	in.Target.ObservedAt, in.Target.FreshUntil = fresh, fresh.Add(5*time.Second)
	in.Capability.ObservedAt, in.Capability.FreshUntil = fresh, fresh.Add(5*time.Second)
	got, err := manualArgumentFixtureRecompile(in, &recording, composition.Resolved, fresh)
	if err != nil || got.ScopeDigest != accepted.ScopeDigest || got.RecipeDigest != accepted.RecipeDigest || !got.Input.Deadline.Equal(accepted.Input.Deadline) || !got.Input.Retention.AnchorAt.Equal(accepted.Input.Retention.AnchorAt) {
		t.Fatal("fixture frozen argument execution scope", err)
	}
	if _, err := manualArgumentFixtureRecompile(in, &recording, nil, fresh); err == nil {
		t.Fatal("missing current catalog facts accepted")
	}
	wrong := append([]planvalue.CatalogProfile(nil), composition.Resolved...)
	wrong[0].SourceUID = "replacement-profile"
	changed, err := manualArgumentFixtureRecompile(in, &recording, wrong, fresh)
	if err == nil && changed.ScopeDigest == accepted.ScopeDigest {
		t.Fatal("replacement profile preserved approved scope")
	}
	in.Target.FreshUntil = fresh
	if _, err := manualArgumentFixtureRecompile(in, &recording, composition.Resolved, fresh); err == nil {
		t.Fatal("expired target accepted during fixture recompile")
	}
}

func manualArgumentSQLComposition(t *testing.T, target targets.PodResolution) planvalue.ProfileComposition {
	t.Helper()
	definition, err := manualArgumentsProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"name": manualArgumentsProfile, "version": "v1", "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	ref := planvalue.ProfileRef{Catalog: "namespace", Name: manualArgumentsProfile, Version: "v1"}
	return planvalue.ProfileComposition{Components: []planvalue.ProfileComponent{{ID: "calls", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s", Resolved: []planvalue.CatalogProfile{{Ref: ref, SourceClusterID: target.Request.ClusterID, SourceNamespaceUID: target.Request.Namespace.UID, SourceUID: "synthetic-argument-profile", Document: raw, Enabled: true}}}
}

// Real reviewed manual grant -> admission -> encrypted intent -> atomic prepare.
// Human/target/process observations remain explicit synthetic component inputs;
// no node collector runs and no fixture row directly supplies observation spend.
func qualifyManualArgumentPreparation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario) {
	t.Helper()
	guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	duty := func(purpose string) *pgxpool.Pool {
		t.Helper()
		// custodyID has a shared prefix; each compiled duty needs its own role.
		role := narrowRole(t, ctx, admin, "manual_arg_"+strings.ReplaceAll(purpose, "-", "_")+"_", "synthetic-manual-argument", func(role string) []string {
			grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, role)
			if !ok {
				t.Fatal("missing compiled duty", purpose)
			}
			return grants
		})
		pool := poolFor(role, "synthetic-manual-argument")
		t.Cleanup(pool.Close)
		return pool
	}
	in := s.a.Plan.Input
	in.Target.ExecutionClass, in.Capability.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	policies, err := s.retention.policies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	composition := manualArgumentSQLComposition(t, in.Target)

	// A normal finite review; this fixture spends no time waiting for preview expiry.
	oldDeadline := now.Add(time.Minute)
	reviewed, err := planning.CompileRecorder(planvalue.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: composition, Retention: in.Retention, Deadline: oldDeadline, NodeRecorder: true, RequireApproval: true}, installedArgumentsCompiler{}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The argument recorder binds its argument-reading assessment rules
	// (RecorderAssessmentRulesFor, PR 149), not only the legacy recorder digest.
	argumentRules, err := planning.RecorderAssessmentRulesForScope(reviewed.CanonicalScope)
	if err != nil || argumentRules == planning.RecorderAssessmentRulesDigest() {
		t.Fatal("argument assessment rules", err)
	}
	p := capture.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: argumentRules,RootID: s.a.RootID, InstallationID: s.a.Recovery.InstallationID, IssuerEpoch: s.a.Recovery.IssuerEpoch, CaptureID: in.CaptureID, CaseID: s.a.CaseID, OccurrenceID: s.a.OccurrenceID, ArtifactID: s.a.Registration.Location.ArtifactID, AttemptID: s.a.Registration.Location.AttemptID, Actor: in.Executor, ExecutionClass: artifact.ContextAPIExecution,
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
	grantPool := duty(manualArgumentHubRolePurpose)
	grants, err := postgres.NewAccessGrants(ctx, grantPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	g := authorization.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: authorization.GrantAdHocCapture, PreviewID: p.ID, CaptureID: p.CaptureID, Target: in.Target.Target(), Requester: p.Actor, ExecutionDigest: p.ScopeDigest, Scope: p.CanonicalScope, Review: []byte(`{}`), DataClass: reviewed.Approval.DataClass, Reasons: reviewed.Approval.Reasons, Lifetime: time.Hour, Revision: 1}
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	g, _, err = grants.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "approval", RequestDigest: sha256.Sum256([]byte("synthetic-request"))}, s.a.Recovery)
	if err != nil {
		t.Fatal("persist grant", err)
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
	in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", RequestedSeconds: in.Retention.RequestedSeconds, AnchorAt: acceptedAt}, acceptedAt)
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
	admissions, err := postgres.NewContextAdmissions(ctx, duty(manualArgumentAdmissionRolePurpose), s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := admissions.AdmitReviewedContext(ctx, p.ID, s.a)
	if err != nil {
		t.Fatal("approved manual argument admission", err)
	}
	if accepted.ScopeDigest != p.ScopeDigest || accepted.CaptureID != p.CaptureID || !accepted.Deadline.Equal(in.Deadline) {
		t.Fatal("approval or execution identity changed")
	}

	e := accepted.Expectation
	if e.NativeType != artifact.SyscallArgumentsArtifact || e.DataClass != "raw" || e.Recording == nil || e.Recording.Arguments == nil {
		t.Fatal("argument admission lost native class", e.NativeType, e.DataClass)
	}
	intentPool := poolFor("capture_audit_runtime", "synthetic-capture-audit")
	defer intentPool.Close()
	intents, err := postgres.NewCaptureIntentAudits(ctx, intentPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
		t.Fatal("encrypted intent acknowledgement", err)
	}
	// The installed hub aggregates execution; its retired standalone duty cannot issue a credential.
	executionPool := grantPool
	executions, err := postgres.NewAPIContextExecutions(ctx, executionPool, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	process := execution.APIProcessBinding{InstallationID: s.a.Recovery.InstallationID, ClusterID: in.Target.Request.ClusterID, IssuerEpoch: s.a.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: custodyID(), BootID: custodyID(), CollectorPodUID: custodyID(), CollectorEpoch: custodyID()}
	refresh := func() executionapp.APIExecutionCheck {
		t.Helper()
		n := time.Now().UTC().Truncate(time.Microsecond)
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
		if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal(err)
		}
		verified := s.a.Eligibility.VerifiedIdentity
		verified.VerifiedAt, verified.ValidUntil = n, n.Add(5*time.Second)
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := executions.ReadAPIContextWork(ctx, e.CaptureUID, verified, recovery)
		if err != nil {
			t.Fatal("original approved API work", err)
		}
		projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.ContextEligibility(verified, projection, s.a.Eligibility.Target, time.Now())
		current := s.a.Plan.Input
		current.Target.ObservedAt, current.Target.FreshUntil = n, n.Add(5*time.Second)
		current.Capability.ObservedAt, current.Capability.FreshUntil = n, n.Add(5*time.Second)
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		current.Retention, err = privacy.Resolve(policies, privacy.Input{Target: current.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		plan, err := manualArgumentFixtureRecompile(current, e.Recording, composition.Resolved, time.Now())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("frozen argument execution scope", err)
		}
		observed := execution.APIProcessObservation{Binding: process, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
		until := n.Add(5 * time.Second)
		for _, d := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, observed.ValidUntil} {
			if d.Before(until) {
				until = d
			}
		}
		checked := time.Now().UTC().Truncate(time.Microsecond)
		check := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: observed, CheckedAt: checked, ValidUntil: until}
		source.ObservedAt, source.FreshUntil = n, until
		if !check.Valid(checked) || !source.Valid(checked) {
			t.Fatal("manual argument fixture current check")
		}
		return check
	}
	read := func(wantBytes, wantEvents int64, wantRecords int) {
		t.Helper()
		var bytes, events int64
		var preparations, sessions int
		err := admin.QueryRow(ctx, `SELECT COALESCE((SELECT spent FROM adhoc_observation_spend WHERE root_id=$1 AND grant_id=$2),0),
 COALESCE((SELECT events_spent FROM adhoc_observation_spend WHERE root_id=$1 AND grant_id=$2),0),
 (SELECT count(*) FROM context_execution WHERE root_id=$1 AND capture_id=$3),
 (SELECT count(*) FROM policy_observation_session WHERE root_id=$1 AND capture_id=$3)`, s.a.RootID, g.ID, e.CaptureUID).Scan(&bytes, &events, &preparations, &sessions)
		if err != nil || bytes != wantBytes || events != wantEvents || preparations != wantRecords || sessions != wantRecords {
			t.Fatal("atomic manual preparation/spend", bytes, events, preparations, sessions, err)
		}
	}
	check := refresh()
	wrong := source
	wrong.PodUID = custodyID()
	if _, first, permit, err := executions.PrepareArgumentRecording(ctx, check, wrong); err == nil || first || permit != (collector.ArgumentObservationPermit{}) {
		t.Fatal("replacement target prepared", first, err)
	}
	read(0, 0, 0)
	check = refresh()
	prepared, first, permit, err := executions.PrepareArgumentRecording(ctx, check, source)
	if err != nil || !first || !permit.ValidFinite(permit.StartedAt) || permit.Binding.CaptureID != e.CaptureUID || permit.Binding.CollectorEpoch != source.CollectorEpoch || permit.Binding.DefinitionDigest != [32]byte(e.Recording.Arguments.DefinitionDigest) || permit.EventCredit != manualArgumentsRate*6 || permit.ByteCredit != 6*planvalue.SensitiveMaxBytesPerSecond {
		t.Fatal("actual manual argument preparation", first, permit, err)
	}
	read(permit.ByteCredit, permit.EventCredit, 1)
	check = refresh()
	again, second, replayed, err := executions.PrepareArgumentRecording(ctx, check, source)
	if err != nil || second || !reflect.DeepEqual(again, prepared) || replayed != permit {
		t.Fatal("passive replay changed original execution/permit", second, err)
	}
	read(permit.ByteCredit, permit.EventCredit, 1)
	wrong = source
	wrong.CollectorEpoch = custodyID()
	if _, first, p, err := executions.PrepareArgumentRecording(ctx, check, wrong); err == nil || first || p != (collector.ArgumentObservationPermit{}) {
		t.Fatal("replacement collector epoch rebound original source", first, err)
	}
	read(permit.ByteCredit, permit.EventCredit, 1)
	for _, query := range []string{"UPDATE policy_observation_session SET event_credit=event_credit WHERE false", "UPDATE adhoc_observation_spend SET spent=spent WHERE false", "UPDATE context_capture SET expectation_json=expectation_json WHERE false"} {
		if _, err := executionPool.Exec(ctx, query); capacitySQLState(err) != "42501" {
			t.Fatal("shared hub credential acquired direct authority mutation", query, err)
		}
	}
	t.Logf("manual raw grant -> admission -> encrypted intent -> PrepareArgumentRecording: one exact execution/session, %d prepaid bytes/%d events, unchanged passive replay and source mismatch refusal", permit.ByteCredit, permit.EventCredit)

}
