package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func argumentPolicyCompositionWire() map[string]any {
	return map[string]any{"components": []any{map[string]any{"id": "calls", "profileRef": map[string]any{"catalog": "namespace", "name": "argument-capture", "version": "v1"}}}, "maxTotalBytes": 8 << 20, "maxDuration": "20s"}
}
func argumentPolicyCompiler(t *testing.T, cluster, namespace string) captureapp.PolicyRecorderCompiler {
	t.Helper()
	raw, err := os.ReadFile("../../internal/application/planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-capture"
	recipe := doc["definition"].(map[string]any)["recipe"].(map[string]any)
	action := recipe["actions"].([]any)[0].(map[string]any)
	action["impact"], action["executionMode"] = "sensitiveRead", "onTrigger"
	action["limits"].(map[string]any)["maxBytes"] = 8 << 20
	params := action["parameters"].(map[string]any)
	params["mode"], params["before"], params["after"] = "arguments", "0s", "3s"
	params["syscalls"] = map[string]any{"mode": "include", "names": []string{"openat"}}
	params["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	params["maxFrozenBytes"] = artifact.RecordingNativeLimit
	recipe["maxTotalBytes"], recipe["maxDuration"] = 8<<20, "20s"
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return captureapp.SingleRecorder(func(wire json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var c contracts.CaptureComposition
		if err := json.Unmarshal(wire, &c); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		composition, err := conversion.CompositionFromWire(c)
		if err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		composition.Resolved = []planvalue.CatalogProfile{{Ref: composition.Components[0].Profile, SourceClusterID: cluster, SourceNamespaceUID: namespace, SourceUID: "synthetic-argument-profile", Document: raw, Enabled: true}}
		return planning.CompilePolicyRecorder(*composition, installedArgumentsCompiler{})
	})
}

func TestPolicyArgumentObservationFixtureCompiles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := policyRecorderOfflineAdmission(t, now)
	a.Plan.Input.Retention.EvidenceType = "syscallTrace"
	raw := publicPolicySpec(t, authorization.AcceptedPolicyAuthority{ClusterID: a.Storage.ClusterID})
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	spec["profileComposition"] = argumentPolicyCompositionWire()
	raw, _ = json.Marshal(spec)
	compiled, err := captureapp.CompilePolicyWithRecorders(t.Context(), targets.Request{}, raw, planning.ContextRecipeName, planning.RecipeDigest(), argumentPolicyCompiler(t, a.Storage.ClusterID, a.Plan.Input.Target.Request.Namespace.UID))
	if err != nil || compiled.Recorder == nil || !compiled.Recorder.Valid() {
		t.Fatal("finite argument policy fixture", err)
	}
	want, err := (installedArgumentsCompiler{}).CompileArguments([]string{"openat"}, false, 128)
	if err != nil || compiled.Recorder.Arguments == nil || *compiled.Recorder.Arguments != want {
		t.Fatal("fixture lost production mechanism pins", err)
	}
	a, preview := buildPolicyRecorderAdmissionFixture(t, a, compiled.Recorder.Composition, installedArgumentsCompiler{}, false, now)
	requirePolicyRecorderAdmissionFixture(t, a, preview, now)
	r, _, err := planning.RecordingForContext(a.Plan)
	if err != nil || r.Arguments == nil || *r.Arguments != want || r.RequireApproval {
		t.Fatal("actual finite recording fixture", err)
	}
	input := a.Plan.Input
	input.Recorder, err = planning.RecorderContextFor(&r)
	if err != nil {
		t.Fatal(err)
	}
	input.Recorder.Composition.Resolved = compiled.Recorder.Composition.Resolved
	replay, err := planning.CompileContext(input, now)
	if err != nil || replay.ScopeDigest != a.Plan.ScopeDigest {
		t.Fatal("original namespace profile facts/frozen mechanism", err)
	}
	for _, purpose := range []string{"hub-runtime", "capture-admit", "context-verify"} {
		if grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, "synthetic_role"); !ok || len(grants) == 0 {
			t.Fatal("unsupported fixture role purpose", purpose)
		}
	}
}
func qualifyArgumentObservationCompanion(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, admissions *postgres.ContextAdmissions, current *postgres.AutomationAuthorities, authority authorization.AcceptedPolicyAuthority, admission capture.Admission, accepted capture.Accepted, acceptance, grant string) {
	t.Helper()
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	guards := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	executions, err := postgres.NewAPIContextExecutions(ctx, hub, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := postgres.NewPolicyTriggers(ctx, hub, s.a.RootID, authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	intentPool := poolFor("capture_audit_runtime", "synthetic-capture-audit")
	defer intentPool.Close()
	intents, err := postgres.NewCaptureIntentAudits(ctx, intentPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
		t.Fatal(err)
	}
	e := accepted.Expectation
	if e.NativeType != artifact.SyscallArgumentsArtifact || e.Recording == nil || e.Recording.Arguments == nil || e.DataClass != "raw" {
		t.Fatal("actual argument expectation", e)
	}
	process := executionvalue.APIProcessBinding{InstallationID: authority.InstallationID, ClusterID: authority.ClusterID, IssuerEpoch: admission.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	node, boot, collectorPod, epoch := custodyID(), custodyID(), custodyID(), custodyID()
	var previewID string
	if err := admin.QueryRow(ctx, `SELECT preview_id::text FROM context_capture WHERE root_id=$1 AND id=$2`, s.a.RootID, accepted.CaptureID).Scan(&previewID); err != nil {
		t.Fatal("actual raw admission preview", err)
	}
	replayChecked := false
	refresh := func() (executionapp.APIExecutionCheck, targets.PacketSourceObservation) {
		t.Helper()
		n := clock()
		s.batch.ObservedAt, s.batch.FreshUntil, s.batch.Initial = n, n.Add(5*time.Second), nil
		if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
			t.Fatal("companion current permission facts", err)
		}
		verified := authorization.PolicyExecutorIdentity(authority, n, n.Add(5*time.Second))
		projection, err := current.PolicyAutomationAuthority(ctx, authority, admission.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligible := authorization.PolicyContextEligibility(verified, authority, projection, admission.Eligibility.Target, clock())
		if !eligible.Eligible {
			t.Fatal("companion accepted team eligibility", eligible.Reason)
		}
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !replayChecked {
			replay, found, err := admissions.LookupContextAdmission(ctx, capture.ReplayQuery{RootID: s.a.RootID, PreviewID: previewID, IdempotencyKey: admission.IdempotencyKey, SubmissionDigest: admission.SubmissionDigest, Identity: verified, Recovery: recovery})
			if err != nil || !found || !replay.Replay || replay.CaptureID != accepted.CaptureID || replay.ScopeDigest != accepted.ScopeDigest || !replay.Deadline.Equal(accepted.Deadline) || replay.Expectation.Recording == nil || replay.Expectation.Recording.RequireApproval {
				t.Fatal("actual raw policy admission replay with require-all false", found, err)
			}
			replayChecked = true
			t.Log("actual raw policy admission replay retained capture/scope/deadline and require-all=false")
		}
		work, err := executions.ReadAPIContextWork(ctx, accepted.CaptureID, verified, recovery)
		if err != nil {
			t.Fatal("actual raw API work", err)
		}
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		input := admission.Plan.Input
		targetAt := clock()
		input.Target.ObservedAt, input.Target.FreshUntil = targetAt, targetAt.Add(5*time.Second)
		input.Capability.ObservedAt, input.Capability.FreshUntil = targetAt, targetAt.Add(5*time.Second)
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: input.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: e.Type().EvidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, clock())
		if err != nil {
			t.Fatal(err)
		}
		input.Recorder, err = planning.RecorderContextFor(e.Recording)
		if err != nil {
			t.Fatal(err)
		}
		input.Recorder.Composition.Resolved = admission.Plan.Input.Recorder.Composition.Resolved
		plan, err := planning.CompileContext(input, clock())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("actual raw frozen context plan", err)
		}
		observed := executionvalue.APIProcessObservation{Binding: process, CheckedAt: targetAt, ValidUntil: targetAt.Add(5 * time.Second)}
		checked := clock()
		until := checked.Add(5 * time.Second)
		for _, bound := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, observed.ValidUntil} {
			until = identity.Earlier(until, bound)
		}
		check := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: observed, CheckedAt: checked, ValidUntil: until}
		source := targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: node, BootID: boot, CollectorPodUID: collectorPod, CollectorEpoch: epoch, ObservedAt: targetAt, FreshUntil: until}
		if !check.Valid(clock()) || !source.Valid(clock()) || source.FreshUntil.After(input.Target.FreshUntil) {
			t.Fatal("assembled actual raw companion preflight invalid")
		}
		return check, source
	}
	read := func(bytes, events int64) {
		t.Helper()
		var pb, pe, gb, ge, prepared, sessions int64
		err := admin.QueryRow(ctx, `SELECT a.observed_bytes_spent,a.observed_events_spent,g.policy_observed_bytes_spent,g.policy_observed_events_spent,(SELECT count(*) FROM context_execution WHERE root_id=a.root_id AND capture_id=$3),(SELECT count(*) FROM policy_observation_session WHERE root_id=a.root_id AND capture_id=$3) FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$4 WHERE a.root_id=$1 AND a.id=$2`, s.a.RootID, acceptance, accepted.CaptureID, grant).Scan(&pb, &pe, &gb, &ge, &prepared, &sessions)
		want := int64(0)
		if events > 0 {
			want = 1
		}
		if err != nil || pb != bytes || gb != bytes || pe != events || ge != events || prepared != want || sessions != want {
			t.Fatal("actual argument atomic graph", pb, pe, gb, ge, prepared, sessions, err)
		}
		status, err := statuses.Status(ctx, authority.PolicyUID)
		if err != nil || status.ObservedEventsSpent != events || status.MaxObservedEvents != authority.Limits.MaxObservedEvents || status.ObservedBytesSpent != bytes || status.MaxObservedBytes != authority.Limits.MaxObservedBytes {
			t.Fatal("public policy status lost original aggregate spend/limits", status.ObservedEventsSpent, status.MaxObservedEvents, err)
		}
	}
	read(0, 0)
	check, source := refresh()
	source.FreshUntil = clock().Add(300 * time.Millisecond)
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, "SELECT id FROM access_grant WHERE root_id=$1 AND id=$2 FOR UPDATE", s.a.RootID, grant); err != nil {
		t.Fatal(err)
	}
	type result struct {
		execution executionvalue.APIExecution
		first     bool
		permit    collector.ArgumentObservationPermit
		err       error
	}
	done := make(chan result, 1)
	go func() {
		x, first, p, err := executions.PrepareArgumentRecording(ctx, check, source)
		done <- result{x, first, p, err}
	}()
	// Observe the actual lock wait, then expire only the original source proof.
	for end := time.Now().Add(time.Second); ; {
		var waiting bool
		if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%access_grant%')`, hub.Config().ConnConfig.User).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(end) {
			t.Fatal("argument preparation never reached original grant lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if wait := time.Until(source.FreshUntil.Add(25 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err == nil || got.first || got.permit != (collector.ArgumentObservationPermit{}) {
			t.Fatal("expired original source issued argument permit", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("argument lock waiter did not join")
	}
	read(0, 0)
	check, source = refresh()
	parallel := make(chan result, 4)
	for range cap(parallel) {
		go func() {
			x, first, p, err := executions.PrepareArgumentRecording(ctx, check, source)
			parallel <- result{x, first, p, err}
		}()
	}
	var execution executionvalue.APIExecution
	var permit collector.ArgumentObservationPermit
	firstCount := 0
	for i := range cap(parallel) {
		got := <-parallel
		if got.err != nil {
			t.Error("concurrent original preparation", got.err)
		}
		if got.first {
			firstCount++
		}
		if i == 0 {
			execution, permit = got.execution, got.permit
		} else if got.permit != permit || !reflect.DeepEqual(got.execution, execution) {
			t.Error("concurrent caller received a different original permit/execution")
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	if firstCount != 1 || !permit.ValidFinite(clock()) || permit.Duration != 3*time.Second || permit.EventCredit != 10 || permit.ByteCredit != 64<<20 || permit.Binding.ProgramDigest != [32]byte(e.Recording.Arguments.ProgramDigest) || permit.Binding.DefinitionDigest != [32]byte(e.Recording.Arguments.DefinitionDigest) || permit.Binding.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(e)) || !execution.Binding.NotAfter.Equal(check.ValidUntil) {
		t.Fatal("actual original argument permit", firstCount, permit)
	}
	read(permit.ByteCredit, permit.EventCredit)
	// The accepted policy has ten events left, but its original grant is
	// exhausted. A later transaction cannot keep the first debit when the
	// second pool refuses. This is a pool probe, not a second capture.
	id := func(s string) pgtype.UUID {
		var id pgtype.UUID
		if err := id.Scan(s); err != nil {
			t.Fatal(err)
		}
		return id
	}
	tx, err := hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := custodydb.New(tx)
	n, err := q.SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: id(s.a.RootID), ID: id(acceptance), Bytes: 512, Events: 1})
	if err != nil || n != 1 {
		t.Fatal("remaining accepted event pool", n, err)
	}
	n, err = q.SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: id(s.a.RootID), ID: id(grant), Bytes: 512, Events: 1})
	if err != nil || n != 0 {
		t.Fatal("exhausted original grant accepted more events", n, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	n, err = custodydb.New(hub).SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: id(s.a.RootID), ID: id(acceptance), Bytes: authority.Limits.MaxObservedBytes, Events: 0})
	if err != nil || n != 0 {
		t.Fatal("accepted byte pool exceeded", n, err)
	}
	n, err = custodydb.New(hub).SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: id(s.a.RootID), ID: id(grant), Bytes: authority.Limits.MaxObservedBytes, Events: 0})
	if err != nil || n != 0 {
		t.Fatal("grant byte pool exceeded", n, err)
	}
	read(permit.ByteCredit, permit.EventCredit)
	replay, second, original, err := executions.PrepareArgumentRecording(ctx, check, source)
	if err != nil || second || !reflect.DeepEqual(replay, execution) || original != permit {
		t.Fatal("argument replay refilled or replaced original", second, err)
	}
	source.CollectorEpoch = custodyID()
	if _, first, p, err := executions.PrepareArgumentRecording(ctx, check, source); err == nil || first || p != (collector.ArgumentObservationPermit{}) {
		t.Fatal("argument replay accepted replacement process", first, err)
	}
	read(permit.ByteCredit, permit.EventCredit)
	// Independently credentialed verifier reads the stored source tuple, not the
	// API expectation's intentionally absent node fields or untrusted header.
	verifierRole := narrowRole(t, ctx, admin, "argument_verifier_", "synthetic-argument-verifier", func(role string) []string {
		sql, ok := postgres.PublicRuntimeRoleGrantSQL("context-verify", role)
		if !ok {
			t.Fatal("context verifier role")
		}
		return sql
	})
	verifierPool := poolFor(verifierRole, "synthetic-argument-verifier")
	defer verifierPool.Close()
	publications, err := postgres.NewContextPublications(ctx, verifierPool, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := publications.AcceptedArgumentSource(ctx, e)
	if err != nil || provenance.NodeUID != node || provenance.BootID != boot || provenance.CollectorEpoch != epoch || provenance.SessionID != permit.Binding.SessionID || provenance.Fence != permit.Binding.Fence {
		t.Fatal("independent publisher original source", provenance, err)
	}
	wrong := e
	wrong.Registration.Location.AttemptID = custodyID()
	if _, err = publications.AcceptedArgumentSource(ctx, wrong); err == nil {
		t.Fatal("publisher accepted wrong attempt")
	}
	// A terminal historical session still verifies its retained artifact.
	if _, err = admin.Exec(ctx, "UPDATE policy_observation_session SET ended_at=clock_timestamp() WHERE root_id=$1 AND capture_id=$2", s.a.RootID, accepted.CaptureID); err != nil {
		t.Fatal(err)
	}
	retained, err := publications.AcceptedArgumentSource(ctx, e)
	if err != nil || retained != provenance {
		t.Fatal("ended original provenance lost", retained, err)
	}
	read(permit.ByteCredit, permit.EventCredit)
	for _, statement := range []string{
		"UPDATE policy_observation_session SET event_credit=event_credit+1 WHERE root_id=$1 AND capture_id=$2",
		"UPDATE policy_observation_session SET credit=credit+1 WHERE root_id=$1 AND capture_id=$2",
	} {
		_, err = verifierPool.Exec(ctx, statement, s.a.RootID, accepted.CaptureID)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("publisher SELECT facet lacks exact permission denial", err)
		}
	}
	t.Log("actual argument compiler -> accepted policy/grant -> admission/intent -> API prepare: expired source rolls entire graph back; exactly one dual debit; exact replay and replacement epoch refusal; historical publisher source uses narrow SELECT")
}
