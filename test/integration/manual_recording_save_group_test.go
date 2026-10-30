//go:build cgo && libpcap

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	planningapp "asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

func TestManualRecordingSaveGroupWithRealServices(t *testing.T) {
	qualifySourceSnapshotRealServices(t, true, false, false, 2)
}

func TestManualRecordingSaveGroupCentralSixteenWithRealServices(t *testing.T) {
	qualifySourceSnapshotRealServices(t, true, false, false, 16)
}

func TestManualRecordingSaveGroupCancellationWithRealServices(t *testing.T) {
	qualifySourceSnapshotRealServices(t, true, true, false, 2)
}

func TestManualRecordingSaveGroupWithPolicyGrantRealServices(t *testing.T) {
	qualifySourceSnapshotRealServices(t, true, false, true, 2)
}

// The scope remains the fixture's accepted workload. Only the exact selected
// Pod differs; these are real current accepted retention readers, not a new
// policy or a copied proof with a replacement target.
func manualGroupRetentionPolicies(ctx context.Context, f *retentionEffectFixture, target authorization.Target) (privacy.PolicySet, error) {
	if target == f.target {
		return f.policies(ctx)
	}
	if target.ClusterID != f.target.ClusterID || target.NamespaceUID != f.target.NamespaceUID || target.WorkloadUID != f.target.WorkloadUID {
		return privacy.PolicySet{}, privacy.ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(ctx); err != nil {
		return privacy.PolicySet{}, err
	}
	return (privacyapp.AcceptedRetentionReader{Topology: f.topology, Sources: f.reader, Now: time.Now}).RetentionPolicies(ctx, target)
}

type manualGroupRetainedPolicies struct{ fixture *retentionEffectFixture }

func (r manualGroupRetainedPolicies) RetainedRetentionPolicies(ctx context.Context, target authorization.Target, origins []artifact.RetentionRule) (privacy.PolicySet, error) {
	f := r.fixture
	if target == f.target {
		return f.RetainedRetentionPolicies(ctx, target, origins)
	}
	if target.ClusterID != f.target.ClusterID || target.NamespaceUID != f.target.NamespaceUID || target.WorkloadUID != f.target.WorkloadUID {
		return privacy.PolicySet{}, privacy.ErrUnavailable
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(ctx); err != nil {
		return privacy.PolicySet{}, err
	}
	return (privacyapp.AcceptedRetentionReader{Topology: f.topology, Sources: f.reader, Now: time.Now}).RetainedRetentionPolicies(ctx, target, origins)
}

func prepareManualRecordingSaveGroup(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, parts []policySourceSnapshotAdmissionFixture) (value.RecordingSaveGroupAdmission, []policySourceSnapshotAdmissionFixture) {
	t.Helper()
	slices.SortFunc(parts, func(a, b policySourceSnapshotAdmissionFixture) int {
		if a.Source.Binding.SourceID < b.Source.Binding.SourceID {
			return -1
		}
		if a.Source.Binding.SourceID > b.Source.Binding.SourceID {
			return 1
		}
		return 0
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := parts[0]
	parent := value.ContextPreview{ID: custodyID(), CaptureID: custodyID(), CaseID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: captureapp.RecordingSaveGroupAssessmentRulesDigest(), RootID: first.Admission.RootID, InstallationID: first.Preview.InstallationID, IssuerEpoch: first.Preview.IssuerEpoch, Actor: first.Preview.Actor, ExecutionClass: artifact.ContextAPIExecution, Storage: first.Preview.Storage, CreatedAt: now, SelectionUntil: now.Add(time.Minute), Group: &value.RecordingSaveGroupPreview{Executor: policy.Authority.Executor, PolicyName: policy.Source.Name, PolicyUID: policy.Authority.PolicyUID, ExecutionDigest: policy.Authority.ScopeDigest}}
	parent.Target = first.Source.Target.Request
	parent.Target.PodUID, parent.Target.PodName = "", ""
	parent.Intent = value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: parent.Target.ClusterID, Namespace: parent.Target.Namespace.Name, Kind: parent.Target.Workload.Kind, Name: parent.Target.Workload.Name}, RequestedSeconds: policy.Compiled.RetentionSeconds}
	before, err := time.ParseDuration(policy.Compiled.Recorder.Action.Before)
	if err != nil {
		t.Fatal(err)
	}
	actionTimeout, err := time.ParseDuration(policy.Compiled.Recorder.Action.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	recipeTimeout, err := time.ParseDuration(policy.Compiled.Recorder.Composition.MaxDuration)
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]planningapp.RecordingSaveScopeSource, 0, len(parts))
	for _, part := range parts {
		plan := part.Admission.Plan
		saved := plan.Input.Snapshot
		sources = append(sources, planningapp.RecordingSaveScopeSource{PolicyUID: policy.Authority.PolicyUID, ExecutionDigest: policy.Authority.ScopeDigest, Original: *part.Source.Target, ActionID: saved.ActionID, Kind: policy.Compiled.Recorder.Action.Kind, DefinitionDigest: saved.SourceDefinitionDigest, AudienceDigest: saved.SourceAudienceDigest, ApprovedBefore: before, Before: saved.Request.Before, MaxBytes: saved.Request.MaxBytes, CeilingDigest: artifact.Digest(plan.Input.Capability.Revision.Digest), RetentionDigest: artifact.Digest(plan.Input.Retention.PolicyRevision.Digest)})
	}
	parent.CanonicalScope, parent.ScopeDigest, err = planningapp.CompileRecordingSaveScope(planningapp.RecordingSaveScopeInput{CaptureID: parent.CaptureID, Requester: parent.Actor, Authority: policy.Authority, Sources: sources, IncidentPodLimit: policy.Compiled.IncidentPods, FinalizeTimeout: min(actionTimeout, recipeTimeout), CeilingDigest: sources[0].CeilingDigest, RetentionDigest: sources[0].RetentionDigest}, now)
	if err != nil {
		t.Fatal("full grouped source selection", err)
	}
	group := value.RecordingSaveGroupAdmission{RootID: parent.RootID, IdempotencyKey: "group-" + custodyID(), SubmissionDigest: captureapp.ContextRequestDigest(parent.ID), Recovery: first.Admission.Recovery}
	for index := range parts {
		part := &parts[index]
		a := part.Admission
		input := a.Plan.Input
		input.CaseID = parent.CaseID
		input.Snapshot = input.Snapshot.Clone()
		input.Snapshot.Group = &planvalue.RecordingSaveGroupBinding{ParentCaptureID: parent.CaptureID, SelectionDigest: parent.ScopeDigest, ChildIndex: index, ChildCount: len(parts)}
		input.Snapshot.RecordingSaveScope = slices.Clone(parent.CanonicalScope)
		a.Plan, err = planningapp.CompileContext(input, part.Admission.Plan.CompiledAt)
		if err != nil {
			t.Fatal("group child compilation", index, err)
		}
		a.Plan, a.Registration, err = planningapp.ReanchorRecordingSave(a.Plan, a.Registration, now, policy.Authority.NotAfter)
		if err != nil {
			t.Fatal("shared passive group time", index, err)
		}
		a.CaseID = parent.CaseID
		a.SubmissionDigest = group.SubmissionDigest
		a.IdempotencyKey = fmt.Sprintf("%s-%d", group.IdempotencyKey, index)
		part.Admission = a
		saved := a.Plan.Input.Snapshot
		r := a.Plan.Input.Retention
		audience, err := planningapp.SourceAudienceDigest(a.Eligibility.DefaultAudience)
		if err != nil {
			t.Fatal(err)
		}
		ref := value.RecordingReference{SourceID: part.Source.Binding.SourceID, Fence: part.Source.Binding.Fence, PolicyUID: policy.Authority.PolicyUID, PodUID: part.Source.Binding.PodUID, ActionID: saved.ActionID, BindingDigest: saved.Request.SourceBindingDigest, ExecutionDigest: policy.Authority.ScopeDigest}
		parent.Group.Children = append(parent.Group.Children, value.RecordingSaveGroupChild{Reference: ref, CaptureID: input.CaptureID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID, OccurrenceID: a.OccurrenceID, AssessmentID: part.Preview.AssessmentID, Request: saved.Request, AudienceDigest: audience, CapabilityRevision: input.Capability.Revision, Retention: value.RecordingSaveRetentionReview{PurposeRef: r.PurposeRef, RequestedSeconds: r.RequestedSeconds, MaximumSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, PolicyRevision: r.PolicyRevision}})
		if a.Plan.Input.Deadline.After(parent.Deadline) {
			parent.Deadline = a.Plan.Input.Deadline
		}
		group.Children = append(group.Children, a)
	}
	parent.SelectionUntil = identity.Earlier(parent.SelectionUntil, parent.Deadline)
	group.Preview = parent
	if !captureapp.ValidContextPreview(parent) {
		t.Fatal("compact parent preview invalid")
	}
	for index, child := range group.Children {
		if !captureapp.ReviewedRecordingSaveGroupChild(parent, child) {
			t.Fatal("child not bound to one parent", index)
		}
	}
	return group, parts
}

func manualGroupWindows(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture) string {
	t.Helper()
	var out string
	if err := f.admin.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_array(policy_uid,tat) ORDER BY policy_uid),'[]'::jsonb)::text FROM policy_workload_window WHERE root_id=$1 AND cluster_id=$2 AND workload_uid=$3`, policy.Scenario.a.RootID, policy.Authority.ClusterID, policy.Authority.WorkloadUID).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func qualifyManualRecordingSaveGroup(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, ledger *postgres.PolicySources, original captureapp.PolicySourceAdmission, refresh func(*testing.T) captureapp.PolicySourceCheck, intents auditapp.CaptureOperationPublication, cancellation bool) {
	t.Helper()
	count := policy.Compiled.IncidentPods
	if count < 2 || count > 16 || policy.Compiled.ObservedPods < count {
		t.Fatal("reviewed incident/observation scope cannot cover group", count, policy.Compiled.ObservedPods)
	}
	if count == 16 && (policy.Authority.Limits.MaxBytes < 16*artifact.RecordingNativeLimit || policy.Authority.Limits.MaxExecutions != 1) {
		t.Fatal("sixteen-source case needs preaccepted128MiB and one policy execution")
	}
	sourceStarted := time.Now()
	sources := []captureapp.PolicySourceAdmission{original}
	templates := []captureapp.PolicySourceCheck{refresh(t)}
	for index := 1; index < count; index++ {
		check := refresh(t)
		check.SourceID, check.Fence = custodyID(), custodyID()
		check.Target.Request.PodUID = custodyID()
		check.Target.Request.PodName = fmt.Sprintf("%s-replica-%02d", check.Target.Request.PodName, index)
		check.Target.Pin.UID = check.Target.Request.PodUID
		check.Target.Pin.Name = check.Target.Request.PodName
		check.Node.PodUID = check.Target.Request.PodUID
		retained, err := manualGroupRetentionPolicies(ctx, policy.Scenario.retention, check.Target.Target())
		if err != nil {
			t.Fatal(err)
		}
		check.Retention, err = privacy.Resolve(retained, privacy.Input{Target: check.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: policy.Compiled.RetentionSeconds, AnchorAt: check.ObservedAt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		check.Initial = true
		check.InitialCredit = 1 << 20
		source, err := ledger.AdmitSource(ctx, check)
		if err != nil {
			t.Fatal("additional real source ledger admission", index, err)
		}
		sources = append(sources, source)
		templates = append(templates, check)
	}
	rows, err := ledger.ListSources(ctx, policy.Authority.PolicyUID)
	if err != nil || len(rows) != count {
		t.Fatal("actual source set cardinality", len(rows), err)
	}
	seenSources, seenPods := map[string]bool{}, map[string]bool{}
	for _, source := range sources {
		binding := source.Permit.Binding
		if seenSources[binding.SourceID] || seenPods[binding.PodUID] || !time.Now().Before(source.Permit.LeafUntil) {
			t.Fatal("source duplicate or original leaf expired")
		}
		seenSources[binding.SourceID] = true
		seenPods[binding.PodUID] = true
		found := false
		for _, row := range rows {
			if row.Binding.SourceID == binding.SourceID {
				found = row.Binding == binding && row.Target != nil
			}
		}
		if !found {
			t.Fatal("actual immutable source binding unavailable")
		}
	}
	t.Logf("group_sources=%d additional_source_arm_ms=%d metadata_controls_total=%d", count, time.Since(sourceStarted).Milliseconds(), 2*count+1)
	maximumBytes := min(policy.Compiled.Recorder.Action.MaxBytes, int64(artifact.RecordingNativeLimit))
	prepare := func() (value.RecordingSaveGroupAdmission, []policySourceSnapshotAdmissionFixture) {
		began := time.Now()
		parts := make([]policySourceSnapshotAdmissionFixture, count)
		for index, source := range sources {
			if !time.Now().Before(source.Permit.LeafUntil) {
				t.Fatal("source expired before group preparation", index)
			}
			current := refresh(t)
			current.SourceID, current.Fence = source.Permit.Binding.SourceID, source.Permit.Binding.Fence
			current.Initial = false
			current.ExpectedCredit = source.Permit.Credit
			target := templates[index].Target
			target.ObservedAt, target.FreshUntil = current.ObservedAt, current.ValidUntil
			current.Target = target
			current.Node.PodUID = target.Request.PodUID
			// Each preparation resolves its own accepted retention. An unused first-Pod
			// proof must not accidentally become this sibling's authority.
			current.Retention = privacy.Resolution{}
			parts[index] = prepareManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], policy, source, current, maximumBytes)
		}
		group, parts := prepareManualRecordingSaveGroup(t, ctx, f, policy, parts)
		previews, err := postgres.NewContextPreviews(ctx, f.roles["hub-runtime"], group.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err := previews.CreateRecordingGroupPreview(ctx, group.Preview); err != nil {
			t.Fatal("one protected parent preview", err)
		}
		t.Logf("group_sources=%d preparation_ms=%d original_first_proof_remaining_ms=%d", count, time.Since(began).Milliseconds(), time.Until(manualGroupProofDeadline(group)).Milliseconds())
		return group, parts
	}
	group, parts := prepare()
	admit := func() (value.Accepted, error) {
		until := manualGroupProofDeadline(group)
		call, cancel := context.WithDeadline(ctx, until)
		defer cancel()
		return admissions.AdmitRecordingSaveGroup(call, group)
	}
	before := readManualSaveCounters(t, ctx, f, policy)
	var controlBeforeFull, controlBeforeReplay int64
	if err := f.admin.QueryRow(ctx, `SELECT charged_full,charged_replay FROM context_control_account WHERE root_id=$1 AND allocation_id=$2`, group.RootID, group.Preview.Storage.AllocationID).Scan(&controlBeforeFull, &controlBeforeReplay); err != nil {
		t.Fatal(err)
	}
	windowBefore := manualGroupWindows(t, ctx, f, policy)
	capacityBefore := manualGroupCapacity(t, ctx, f)
	var grantBefore manualPolicyGrantSpend
	if policy.GrantID != "" {
		var limit int64
		if policy.Authority.Limits.MaxExecutions != 1 {
			t.Fatal("group grant case requires reviewed policy limit1")
		}
		if err := f.admin.QueryRow(ctx, `SELECT policy_max_executions FROM access_grant WHERE id=$1`, policy.GrantID).Scan(&limit); err != nil || limit != 2 {
			t.Fatal("group grant case requires reviewed grant starts2", limit, err)
		}
	}
	if policy.GrantID != "" {
		grantBefore = readManualPolicyGrantSpend(t, ctx, f, policy.GrantID)
	}
	t.Run("last-child-failure-rolls-back-whole-group", func(t *testing.T) {
		last := group.Children[len(group.Children)-1].Plan.Input.CaptureID
		if _, err := f.admin.Exec(ctx, `CREATE SEQUENCE public.asservat_group_fixture_reached`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.admin.Exec(ctx, `DROP SEQUENCE public.asservat_group_fixture_reached`); err != nil {
				t.Error(err)
			}
		}()
		function := fmt.Sprintf(`CREATE FUNCTION public.asservat_group_fixture_fail() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF NEW.id='%s'::uuid THEN PERFORM nextval('public.asservat_group_fixture_reached'::regclass); RAISE EXCEPTION 'owned final-child failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$`, last)
		if _, err := f.admin.Exec(ctx, function); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.admin.Exec(ctx, `DROP FUNCTION public.asservat_group_fixture_fail()`); err != nil {
				t.Error(err)
			}
		}()
		if _, err := f.admin.Exec(ctx, `CREATE TRIGGER asservat_group_fixture_fail BEFORE INSERT ON context_capture FOR EACH ROW EXECUTE FUNCTION public.asservat_group_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.admin.Exec(ctx, `DROP TRIGGER asservat_group_fixture_fail ON context_capture`); err != nil {
				t.Error(err)
			}
		}()
		rollbackStarted := time.Now()
		if _, err := admit(); err == nil {
			t.Fatal("forced last-child failure admitted group")
		}
		t.Logf("group_sources=%d test_induced_last_child_rollback_ms=%d", count, time.Since(rollbackStarted).Milliseconds())
		var reached bool
		if err := f.admin.QueryRow(ctx, `SELECT is_called FROM public.asservat_group_fixture_reached`).Scan(&reached); err != nil || !reached {
			t.Fatal("refusal did not reach test-induced final-child trigger", reached, err)
		}
		if manualGroupCapacity(t, ctx, f) != capacityBefore {
			t.Fatal("late refusal retained capacity/control spend")
		}
		if got := readManualSaveCounters(t, ctx, f, policy); got != before || manualGroupWindows(t, ctx, f, policy) != windowBefore {
			t.Fatal("rolled-back group changed policy counters/windows", got, before)
		}
		if policy.GrantID != "" && readManualPolicyGrantSpend(t, ctx, f, policy.GrantID) != grantBefore {
			t.Fatal("rolled-back group spent grant")
		}
		var count int
		if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM recording_save_group WHERE id=$1)+(SELECT count(*) FROM context_capture WHERE group_id=$1)`, group.Preview.CaptureID).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial parent/children retained", count, err)
		}
	})
	group, parts = prepare() // New passive review and current facts after removing the owned fault.
	admittedStarted := time.Now()
	accepted, err := admit()
	if err != nil {
		t.Fatal("actual atomic group admission", err)
	}
	t.Logf("group_sources=%d atomic_admission_ms=%d original_first_proof_remaining_ms=%d configured_output_bytes=%d", count, time.Since(admittedStarted).Milliseconds(), time.Until(manualGroupProofDeadline(group)).Milliseconds(), int64(count)*maximumBytes)
	if accepted.Group == nil || len(accepted.Group.Children) != count || accepted.CaptureID != group.Preview.CaptureID || accepted.Expectation.CaptureUID != "" {
		t.Fatal("group became fake artifact or lost children")
	}
	t.Run("one-parent-shared-t0-policy-and-grant-spend", func(t *testing.T) {
		after := readManualSaveCounters(t, ctx, f, policy)
		var full, chargedReplay int64
		if err := f.admin.QueryRow(ctx, `SELECT charged_full,charged_replay FROM context_control_account WHERE root_id=$1 AND allocation_id=$2`, group.RootID, group.Preview.Storage.AllocationID).Scan(&full, &chargedReplay); err != nil || full != controlBeforeFull+int64(count+1) || chargedReplay != controlBeforeReplay+int64(count+1) {
			t.Fatal("group metadata did not charge parent plus genuine children", full, chargedReplay, err)
		}
		var unsharedManual int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM context_capture WHERE group_id=$1 AND history_origin='manual' AND share_instruction IS NULL`, accepted.CaptureID).Scan(&unsharedManual); err != nil || unsharedManual != count {
			t.Fatal("group inherited recurring sharing or automatic history", unsharedManual, err)
		}
		var childJournals int
		previewIDs := make([]string, len(parts))
		for index, part := range parts {
			previewIDs[index] = part.Preview.ID
		}
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM context_preview WHERE root_id=$1 AND id=ANY($2::uuid[])`, group.RootID, previewIDs).Scan(&childJournals); err != nil || childJournals != 0 {
			t.Fatal("child preview journals were persisted", childJournals, err)
		}
		if after.Executions != before.Executions+1 || after.Collected != before.Collected+int64(count)*maximumBytes || after.Occurrences != before.Occurrences || after.Observed != before.Observed || after.Shares != before.Shares || after.Reservations != before.Reservations+count {
			t.Fatal("wrong grouped policy/resource units", after, before)
		}
		if policy.GrantID != "" {
			afterGrant := readManualPolicyGrantSpend(t, ctx, f, policy.GrantID)
			if afterGrant.Executions != grantBefore.Executions+int64(count) || afterGrant.Bytes != grantBefore.Bytes+int64(count)*maximumBytes || afterGrant.Observed != grantBefore.Observed {
				t.Fatal("grant did not count per source", afterGrant, grantBefore)
			}
		}
		for _, child := range accepted.Group.Children {
			if child.Expectation.Snapshot == nil || !child.CreatedAt.Equal(accepted.CreatedAt) || !child.Expectation.Snapshot.T0.Equal(accepted.CreatedAt) || child.CaptureID == accepted.CaptureID {
				t.Fatal("child shifted t0 or impersonated parent")
			}
		}
		for key, interval := range map[string]time.Duration{"": value.WorkloadTriggerInterval, policy.Authority.PolicyUID: policy.Compiled.Interval} {
			var tat time.Time
			if err := f.admin.QueryRow(ctx, `SELECT tat FROM policy_workload_window WHERE root_id=$1 AND cluster_id=$2 AND workload_uid=$3 AND policy_uid=$4`, group.RootID, policy.Authority.ClusterID, policy.Authority.WorkloadUID, key).Scan(&tat); err != nil || !tat.Equal(accepted.CreatedAt.Add(interval)) {
				t.Fatal("group advanced occurrence window more than once", key, tat, err)
			}
		}
		replayStarted := time.Now()
		replay, err := admit()
		t.Logf("group_sources=%d exact_replay_ms=%d original_first_proof_remaining_ms=%d", count, time.Since(replayStarted).Milliseconds(), time.Until(manualGroupProofDeadline(group)).Milliseconds())
		if err != nil || replay.Group == nil || replay.CaptureID != accepted.CaptureID || !replay.CreatedAt.Equal(accepted.CreatedAt) || readManualSaveCounters(t, ctx, f, policy) != after {
			t.Fatal("group replay changed identity/time/spend", err)
		}
	})

	for index := range parts {
		parts[index].Accepted = accepted.Group.Children[index]
		parts[index].Admission.Plan, parts[index].Admission.Registration, err = planningapp.ReanchorRecordingSave(parts[index].Admission.Plan, parts[index].Admission.Registration, accepted.CreatedAt, policy.Authority.NotAfter)
		if err != nil {
			t.Fatal(err)
		}
	}
	if count > 2 {
		t.Run("sixteen-central-only-no-execution-or-native", func(t *testing.T) {
			var executions, catalog int
			if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM context_execution e JOIN context_capture c ON c.id=e.capture_id WHERE c.group_id=$1),(SELECT count(*) FROM context_catalog x JOIN context_capture c ON c.id=x.capture_id WHERE c.group_id=$1)`, accepted.CaptureID).Scan(&executions, &catalog); err != nil || executions != 0 || catalog != 0 {
				t.Fatal("central-only case dispatched or published native work", executions, catalog, err)
			}
			qualifyManualGroupCentralProgress(t, ctx, f, policy, accepted, parts[0].Admission.RecordingSave.Initiator.VerifiedIdentity)
		})
	} else {
		for index := range parts {
			part := parts[index]
			t.Run(fmt.Sprintf("native-child-%d", index), func(t *testing.T) { qualifySourceSnapshotCompletion(t, ctx, f, policy, part, intents) })
			if cancellation && index == 0 {
				qualifyManualRecordingSaveGroupMixedCancellation(t, ctx, f, policy, accepted, parts[1])
				break
			}
		}
	}
	t.Run("one-encrypted-parent-history-fresh-selection-settings", func(t *testing.T) {
		qualifyManualRecordingSaveGroupHistory(t, ctx, f, policy, group.Preview, accepted, parts[0].Admission.RecordingSave.Initiator.VerifiedIdentity)
	})
}

func manualGroupCapacity(t *testing.T, ctx context.Context, f *capacitySQLFixture) string {
	t.Helper()
	var out string
	if err := f.admin.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT COALESCE(jsonb_agg(jsonb_build_array(id,charged_bytes,charged_objects) ORDER BY id),'[]'::jsonb) FROM custody_allocation),
 (SELECT count(*) FROM context_control_charge),
 (SELECT COALESCE(jsonb_agg(jsonb_build_array(root_id,allocation_id,charged_full,charged_replay) ORDER BY root_id,allocation_id),'[]'::jsonb) FROM context_control_account),
 (SELECT count(*) FROM recording_save_reservation),
 (SELECT count(*) FROM custody_attempt))::text`).Scan(&out); err != nil {
		t.Fatal("bounded owned fixture capacity counters", err)
	}
	return out
}

func qualifyManualRecordingSaveGroupMixedCancellation(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, parent value.Accepted, pending policySourceSnapshotAdmissionFixture) {
	t.Helper()
	before := readManualSaveCounters(t, ctx, f, policy)
	var originalSources string
	if err := f.admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(s) ORDER BY id)::text FROM policy_recording_source s WHERE root_id=$1 AND policy_uid=$2`, pending.Admission.RootID, policy.Authority.PolicyUID).Scan(&originalSources); err != nil {
		t.Fatal(err)
	}
	f.refreshBase(t)
	recovery, err := policy.Scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	human := pending.Admission.RecordingSave.Initiator.VerifiedIdentity
	human.VerifiedAt, human.ValidUntil = now, now.Add(5*time.Second) // Explicit synthetic current identity, real SQL permissions below.
	reader, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], pending.Admission.RootID, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	query := value.ProgressQuery{RootID: pending.Admission.RootID, CaptureID: parent.CaptureID, Identity: human, Recovery: recovery}
	progress, err := reader.ReadContextProgress(ctx, query)
	if err != nil || len(progress.Actions) != 2 {
		t.Fatal("real parent progress before mixed cancellation", err)
	}
	guards := postgres.EffectTransactionGuards{Recovery: policy.Scenario.recovery.guard, Retention: policy.Scenario.retention.guard}
	executions, err := postgres.NewAPIContextExecutions(ctx, f.roles["hub-runtime"], pending.Admission.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	checked := time.Now().UTC().Truncate(time.Microsecond)
	check := value.CancellationCheck{RootID: pending.Admission.RootID, Identity: human, Recovery: recovery, CheckedAt: checked, ValidUntil: identity.Earlier(human.ValidUntil, recovery.FreshUntil), Request: value.CancellationRequest{CaptureID: parent.CaptureID, ExpectedRevision: progress.Revision, IdempotencyKey: "cancel-selected-group"}}
	decision, err := executions.RequestCaptureCancellation(ctx, check)
	if err != nil || !decision.Decision.Requested {
		t.Fatal("parent cancellation did not request only remaining child", err)
	}
	replay, err := executions.RequestCaptureCancellation(ctx, check)
	if err != nil || replay.Decision.Revision != decision.Decision.Revision {
		t.Fatal("group cancellation replay changed revision", err)
	}
	progress, err = reader.ReadContextProgress(ctx, query)
	if err != nil || progress.Phase != "Partial" || len(progress.Actions) != 2 {
		t.Fatal("mixed output/cancel status lost", progress.Phase, err)
	}
	phases := map[string]string{}
	for _, action := range progress.Actions {
		phases[action.InstanceID] = action.Phase
	}
	if phases[parent.Group.Children[0].CaptureID] != "Succeeded" || phases[pending.Accepted.CaptureID] != "Cancelled" {
		t.Fatal("parent cancellation removed committed sibling or left pending child", phases)
	}
	var sourceAfter string
	if err := f.admin.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(s) ORDER BY id)::text FROM policy_recording_source s WHERE root_id=$1 AND policy_uid=$2`, pending.Admission.RootID, policy.Authority.PolicyUID).Scan(&sourceAfter); err != nil || sourceAfter != originalSources {
		t.Fatal("group cancellation changed independently authorized source", err)
	}
	if readManualSaveCounters(t, ctx, f, policy) != before {
		t.Fatal("group cancellation refunded/repeated shared spend")
	}
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM context_execution WHERE root_id=$1 AND capture_id=$2`, pending.Admission.RootID, pending.Accepted.CaptureID).Scan(&count); err != nil || count != 0 {
		t.Fatal("unstarted cancelled child acquired execution", count, err)
	}
}

func TestManualRecordingSaveGroupFixtureFundsSourcesParentAndChildren(t *testing.T) {
	for _, count := range []int{2, 16} {
		t.Run(fmt.Sprintf("sources-%d", count), func(t *testing.T) {
			root, installation, cluster, control := custodyID(), custodyID(), custodyID(), custodyID()
			q, template := capacityNativeQualification(t, root, installation, cluster, control, "synthetic-group-account")
			f := &capacitySQLFixture{qualification: q, template: template}
			configureManualGroupSourceCapacity(f, count)
			backing, err := capacity.CompileContextProtocolBacking(f.template.Policies[0].Budget.Context, q.RootBacking.ContextHistory)
			if err != nil || backing.Records < int64(2*count+1) || backing.ReplayRecords < int64(2*count+1) {
				t.Fatal("real sources plus parent and children underfunded", count, backing.Records, backing.ReplayRecords, err)
			}
			plan, err := capacity.CompileProtectedPoolPlan(f.template, f.template.Pools[0].Budget.Name)
			if err != nil {
				t.Fatal(err)
			}
			qualified, err := capacity.CompileQualifiedRootBacking(f.qualification, plan)
			if err != nil {
				t.Fatal("group configuration lacks protected root backing", err)
			}
			raw, _ := qualified.Canonical()
			var compiled struct{ Input capacity.RootBackingInput }
			if err := json.Unmarshal(raw, &compiled); err != nil {
				t.Fatal(err)
			}
			if compiled.Input.RecordsPerAccount < backing.Records {
				t.Fatal("compiled root has fewer records than workload protocol", compiled.Input.RecordsPerAccount, backing.Records)
			}
			slots := compiled.Input.Accounts * compiled.Input.RecordsPerAccount
			if compiled.Input.Capture.RecordsPerAccount != compiled.Input.RecordsPerAccount || compiled.Input.Capture.Policy.MetadataSlots != slots || compiled.Input.ProcessingState.MaxCaptures < slots {
				t.Fatal("capture/processing root does not cover grouped records")
			}
			b, w := compiled.Input.Capture.Policy.History.SlotBacking(compiled.Input.Capture.Policy.MaxPurgeLeases)
			if compiled.Input.Capture.Policy.BackupReservedBytes != slots*b || compiled.Input.Capture.Policy.WALReservedBytes != slots*w {
				t.Fatal("capture lane backup/WAL underfunded")
			}
			pb, pw, ok := compiled.Input.ProcessingState.RequiredBytes()
			if !ok || compiled.Input.ProcessingState.BackupBytes < pb || compiled.Input.ProcessingState.WALBytes < pw {
				t.Fatal("processing state backup/WAL underfunded")
			}
			t.Logf("root_records_per_account=%d capture_records_per_account=%d capture_metadata_slots=%d processing_max_captures=%d capture_backup=%d capture_wal=%d processing_backup=%d processing_wal=%d", compiled.Input.RecordsPerAccount, compiled.Input.Capture.RecordsPerAccount, compiled.Input.Capture.Policy.MetadataSlots, compiled.Input.ProcessingState.MaxCaptures, compiled.Input.Capture.Policy.BackupReservedBytes, compiled.Input.Capture.Policy.WALReservedBytes, compiled.Input.ProcessingState.BackupBytes, compiled.Input.ProcessingState.WALBytes)
			nativeUnit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
			if f.template.Policies[0].Budget.Context.Bytes < int64(count)*nativeUnit {
				t.Fatal("genuine output reservations underfunded")
			}
			t.Logf("configured group%d controls=%d (%dsources+1parent+%dchildren); native_output_ceiling=%d; arithmetic only", count, backing.Records, count, count, int64(count)*artifact.RecordingNativeLimit)
		})
	}
}

func configureManualGroupSourceCapacity(f *capacitySQLFixture, count int) {
	configureManualSourceCapacity(f)
	unit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	protected := capacity.BudgetAmount{Bytes: int64(max(3, count+1)) * unit, Objects: int64(2*count+1) * 4}
	p := f.template.Policies[0].Budget
	p.Protected, p.Hard, p.Context = protected, protected, protected
	p.NamespaceMaximum = capacity.BudgetAmount{Bytes: capacityNativeAccounts * protected.Bytes, Objects: capacityNativeAccounts * protected.Objects}
	f.template.Pools[0].Budget.Slots[0].Protected = protected
	// Configure the protected root before its qualification is serialized and
	// accepted. Workload object capacity alone does not enlarge root coverage.
	records := int64(2*count + 1)
	root := &f.qualification.RootBacking
	root.RecordsPerAccount = records
	root.Capture.RecordsPerAccount = records
	slots := root.Accounts * records
	backup, wal := root.Capture.Policy.History.SlotBacking(root.Capture.Policy.MaxPurgeLeases)
	root.Capture.Policy.MetadataSlots = slots
	root.Capture.Policy.BackupReservedBytes = slots * backup
	root.Capture.Policy.WALReservedBytes = slots * wal
	root.ProcessingState.MaxCaptures = slots
	var ok bool
	root.ProcessingState.BackupBytes, root.ProcessingState.WALBytes, ok = root.ProcessingState.RequiredBytes()
	if !ok {
		panic("invalid bounded grouped fixture processing backing")
	}
}

// Synthetic regional routing only: authority comes from the real SQL ledger,
// and encrypted objects/receipts come from the real object-store adapter. This
// does not qualify installed signed history transport or long-lived cleanup.
type manualGroupHistoryDispatcher struct{ store *objectstore.Store }
type manualGroupHistorySession struct {
	store                   *objectstore.Store
	cluster, capture, epoch string
	until                   time.Time
}

func (d manualGroupHistoryDispatcher) PrepareHistory(ctx context.Context, cluster, capture string) (fleetapp.HistorySession, error) {
	until := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	return &manualGroupHistorySession{store: d.store, cluster: cluster, capture: capture, epoch: custodyID(), until: until}, nil
}
func (s *manualGroupHistorySession) ExecutorEpoch() string { return s.epoch }
func (s *manualGroupHistorySession) NotAfter() time.Time   { return s.until }
func (s *manualGroupHistorySession) Close()                {}
func (s *manualGroupHistorySession) ExecuteHistory(ctx context.Context, a value.HistoryOperationAuthority, b value.HistoryCiphertexts, c artifact.Copies) (fleetapp.HistoryReply, error) {
	var out fleetapp.HistoryReply
	e := a.Expectation
	if !a.Valid(time.Now()) || a.ExecutorEpoch != s.epoch || e.CaptureID != s.capture || e.Registration.Location.ClusterID != s.cluster {
		return out, value.ErrDenied
	}
	objects := objectstore.HistoryObjects{Store: s.store, StoreID: e.Registration.StoreID}
	call, cancel := context.WithDeadline(ctx, identity.Earlier(a.NotAfter, s.until))
	defer cancel()
	switch a.Operation {
	case "write":
		digest, err := value.HistoryCiphertextsDigest(b)
		if err != nil || digest != a.BundleDigest {
			return out, artifact.ErrIntegrity
		}
		copies, err := objects.Write(call, e, b)
		if err != nil {
			return out, err
		}
		if !a.Valid(time.Now()) || call.Err() != nil {
			return out, value.ErrChanged
		}
		completion := value.HistoryWriterCompletion{RootID: e.RootID, CaptureID: e.CaptureID, AttemptID: e.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: s.epoch, ExpectationDigest: value.HistoryExpectationDigest(e), CopiesDigest: value.HistoryCopiesDigest(copies), CompletedAt: time.Now().UTC().Truncate(time.Microsecond), NotAfter: a.NotAfter}
		out.Copies, out.WriterCompletion = copies, &completion
	case "read":
		if !fleetapp.HistoryCopiesMatch(a, c) {
			return out, artifact.ErrIntegrity
		}
		bundle, err := objects.Read(call, e, c)
		if err != nil {
			return out, err
		}
		if !a.Valid(time.Now()) || call.Err() != nil {
			bundle.Clear()
			return out, value.ErrChanged
		}
		out.Bundle, out.Copies = bundle, c
	default:
		return out, value.ErrDenied
	}
	return out, nil
}

type manualGroupHistoryRetention struct{ fixture *retentionEffectFixture }

func (r manualGroupHistoryRetention) resolver() privacyapp.RetentionResolver {
	reader := privacyapp.AcceptedRetentionReader{Topology: r.fixture.topology, Sources: r.fixture.reader, Now: time.Now}
	return privacyapp.RetentionResolver{Policies: reader, RetainedPolicies: reader, Now: time.Now}
}
func (r manualGroupHistoryRetention) ResolveCaseMetadata(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	f := r.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(ctx); err != nil {
		return privacy.Resolution{}, err
	}
	return r.resolver().ResolveCaseMetadata(ctx, in)
}
func (r manualGroupHistoryRetention) ResolveRetainedCaseMetadata(ctx context.Context, in privacy.Input, previous privacy.Deadlines, origins []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	f := r.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.observe(ctx); err != nil {
		return privacy.RetainedResolution{}, err
	}
	return r.resolver().ResolveRetainedCaseMetadata(ctx, in, previous, origins)
}

func qualifyManualRecordingSaveGroupHistory(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, preview value.ContextPreview, accepted value.Accepted, human identity.Identity) {
	t.Helper()
	draft, err := captureapp.HistoryDraftFromPreview(preview, accepted)
	if err != nil || draft.RecordingSave == nil || draft.Selection != "recordingSelectionRequired" {
		t.Fatal("actual parent recording-save history draft", err)
	}
	material := f.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	guards := postgres.EffectTransactionGuards{Recovery: policy.Scenario.recovery.guard, Retention: policy.Scenario.retention.guard}
	ledger, err := postgres.NewHistoryParameters(ctx, f.roles["hub-runtime"], preview.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], preview.RootID, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	service := captureapp.HistoryParameterService{RootID: preview.RootID, InstallationID: preview.InstallationID, Ledger: ledger, Regional: manualGroupHistoryDispatcher{store: f.store}, Codec: objectstore.HistoryCodec{Sealer: f.keys, Opener: f.keys, Keys: mac}, Keys: mac, Recovery: policy.Scenario.recovery.reader, Retention: manualGroupHistoryRetention{fixture: policy.Scenario.retention}, Legacy: legacy, Limits: value.HistoryLimits{PerSelector: 10, PerInstallation: 100}, NewID: custodyID, Now: time.Now}
	f.refreshBase(t)
	human.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	human.ValidUntil = human.VerifiedAt.Add(5 * time.Second)
	if err := service.Persist(ctx, accepted, human, draft, nil); err != nil {
		t.Fatal("real encrypted grouped history persistence", err)
	}
	recovery, err := policy.Scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := captureapp.HistorySelectorKey(mac, preview.RootID, draft.Selector())
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListCaptureHistory(ctx, value.HistoryQuery{RootID: preview.RootID, Target: authorization.WorkloadScope(policy.Authority.ClusterID, policy.Authority.NamespaceUID, policy.Authority.WorkloadUID), SelectorKey: selector, Origins: []value.HistoryOrigin{value.HistoryManual}, Limit: 20, Identity: human, Recovery: recovery})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].CaptureID != accepted.CaptureID || page.Entries[0].Operation != "recordingSave" {
		t.Fatal("group history duplicated children or lost parent", len(page.Entries), err)
	}
	settings, err := service.ReadCaptureSettings(ctx, value.SettingsQuery{RootID: preview.RootID, CaptureID: accepted.CaptureID, Identity: human, Recovery: recovery})
	if err != nil || settings.RecordingSave == nil || settings.Selection != "recordingSelectionRequired" || !settings.AcceptedAt.Equal(accepted.CreatedAt) || settings.RecordingSave.PolicyExecutionDigest != policy.Authority.ScopeDigest {
		t.Fatal("actual encrypted grouped settings lost original scope/time", err)
	}
	if len(settings.RecordingSave.Windows) != 1 || settings.RecordingSave.Windows[0].ActionID != policy.Compiled.Recorder.Action.ID {
		t.Fatal("repeat settings invented per-Pod actions")
	}
	var summaries int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM capture_history_parameter WHERE root_id=$1`, preview.RootID).Scan(&summaries); err != nil || summaries != 1 {
		t.Fatal("group did not store one settings envelope", summaries, err)
	}
}

func manualGroupProofDeadline(group value.RecordingSaveGroupAdmission) time.Time {
	until := group.Preview.SelectionUntil
	for _, child := range group.Children {
		until = identity.Earlier(until, identity.Earlier(child.Eligibility.ValidUntil, identity.Earlier(child.RecordingSave.Initiator.ValidUntil, child.Plan.ValidUntil)))
	}
	return until
}

func qualifyManualGroupCentralProgress(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, parent value.Accepted, human identity.Identity) {
	t.Helper()
	f.refreshBase(t)
	recovery, err := policy.Scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	human.VerifiedAt, human.ValidUntil = now, now.Add(5*time.Second)
	reader, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := reader.ReadContextProgress(ctx, value.ProgressQuery{RootID: policy.Scenario.a.RootID, CaptureID: parent.CaptureID, Identity: human, Recovery: recovery})
	if err != nil || len(progress.Actions) != 16 || progress.CaptureID != parent.CaptureID || progress.Phase == "Succeeded" || progress.CandidateArtifactID != "" {
		t.Fatal("central-only parent progress lost real children or invented result", len(progress.Actions), progress.Phase, err)
	}
	states := map[string]string{}
	for _, action := range progress.Actions {
		states[action.InstanceID] = action.PodUID
		if action.Phase == "Succeeded" {
			t.Fatal("central-only child reported native success")
		}
	}
	for _, child := range parent.Group.Children {
		if states[child.CaptureID] != child.Expectation.PodUID {
			t.Fatal("progress substituted a child instance or Pod")
		}
	}
	var memberCount, sourceCount, pods int
	if err := f.admin.QueryRow(ctx, `SELECT cardinality(g.child_ids),jsonb_array_length(convert_from(g.scope_json,'UTF8')::jsonb->'sources'),(SELECT count(DISTINCT convert_from(c.expectation_json,'UTF8')::jsonb->>'PodUID') FROM context_capture c WHERE c.group_id=g.id) FROM recording_save_group g WHERE g.id=$1`, parent.CaptureID).Scan(&memberCount, &sourceCount, &pods); err != nil || memberCount != 16 || sourceCount != 16 || pods != 16 {
		t.Fatal("actual SQL group/cardinality differs from reviewed16", memberCount, sourceCount, pods, err)
	}
	t.Logf("actual_group_header_members=%d canonical_sources=%d distinct_child_pods=%d progress_actions=%d phase=%s; no execution/native qualification", memberCount, sourceCount, pods, len(progress.Actions), progress.Phase)
}
