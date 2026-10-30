//go:build cgo && libpcap

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/pcap"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	planningapp "asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/presentation"
)

// The actual application/SQL/runner/custody workflow runs together here.
// Identity verification, process/source observations and local start
// attestations remain synthetic. No regional socket/installed collector claim.
func TestManualRecordingSaveDispatchWorkflowWithRealServices(t *testing.T) {
	qualifySourceSnapshotServicesMode(t, sourceSnapshotQualificationMode{manual: true, groupCount: 2, dispatch: true})
}

// This standalone maximum fanout uses its own pristine service fixture.
func TestManualRecordingSaveDispatchWorkflow16WithRealServices(t *testing.T) {
	qualifySourceSnapshotServicesMode(t, sourceSnapshotQualificationMode{manual: true, groupCount: 16, dispatch: true})
}

// A different independently initialized fixture prospectively authors30s
// completion. It tests one real request owner across admission and all starts.
func TestManualRecordingSaveRequest16ThirtySecondProfileWithRealServices(t *testing.T) {
	qualifySourceSnapshotServicesMode(t, sourceSnapshotQualificationMode{manual: true, groupCount: 16, dispatch: true, dispatchRequest: true})
}

type dispatchPolicyDocuments struct{ policy policySourceAcceptedFixture }

func (d dispatchPolicyDocuments) ReadPolicy(ctx context.Context, name, uid string) (value.PolicySource, []byte, error) {
	if ctx.Err() != nil || name != d.policy.Source.Name || uid != d.policy.Source.Revision.UID {
		return value.PolicySource{}, nil, value.ErrUnavailable
	}
	// Original authored input is explicitly synthetic, but it is the exact real
	// compiler/SQLacceptance input. Current accepted authority is read separately.
	return d.policy.Source, bytes.Clone(d.policy.RawSpec), nil
}

// Bounded test-only inclusive timings. Each wrapper delegates exactly once
// with the original context/arguments and returns the same value/error.
type dispatchPortSample struct {
	count    int
	sum, max time.Duration
}
type dispatchPortTimes struct {
	mu    sync.Mutex
	ports [5]dispatchPortSample
}

func (s *dispatchPortTimes) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ports = [5]dispatchPortSample{}
}
func (s *dispatchPortTimes) add(port int, began time.Time) {
	d := time.Since(began)
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.ports[port]
	p.count++
	p.sum += d
	if d > p.max {
		p.max = d
	}
}
func (s *dispatchPortTimes) report(t *testing.T) {
	s.mu.Lock()
	snapshot := s.ports
	s.mu.Unlock()
	for n, name := range [5]string{"recovery", "approvals", "eligibility-policy", "eligibility-human", "eligibility-unknown"} {
		p := snapshot[n]
		if p.count > 0 {
			t.Logf("actual_investigation_port kind=%s count=%d inclusive_sum_us=%d max_us=%d", name, p.count, p.sum.Microseconds(), p.max.Microseconds())
		}
	}
}

type dispatchTimedEligibility struct {
	base  captureapp.ContextEligibilityReader
	times *dispatchPortTimes
}

func (s dispatchTimedEligibility) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	began := time.Now()
	out := s.base.ContextEligibilityCurrent(ctx, current, target)
	port := 4
	if out.Principal.Valid() {
		if _, _, policy := authorization.PolicyExecutor(out.Principal); policy {
			port = 2
		} else if out.Principal.Kind == identity.Human {
			port = 3
		}
	}
	s.times.add(port, began)
	return out
}

type dispatchTimedApprovals struct {
	base  captureapp.ApprovalSettings
	times *dispatchPortTimes
}

func (s dispatchTimedApprovals) IdentityPolicy(ctx context.Context, issuer string) (identity.Policy, error) {
	began := time.Now()
	out, err := s.base.IdentityPolicy(ctx, issuer)
	s.times.add(1, began)
	return out, err
}

type dispatchTimedRecovery struct {
	base  fleetapp.RecoveryReader
	times *dispatchPortTimes
}

func (s dispatchTimedRecovery) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	began := time.Now()
	out, err := s.base.RecoveryState(ctx)
	s.times.add(0, began)
	return out, err
}

type dispatchGroupAdmissions struct {
	t        *testing.T
	base     *postgres.ContextAdmissions
	request  value.RecordingSaveGroupAdmission
	accepted value.Accepted
	calls    int
}

func (s *dispatchGroupAdmissions) AdmitRecordingSaveGroup(ctx context.Context, in value.RecordingSaveGroupAdmission) (value.Accepted, error) {
	began := time.Now()
	s.calls++
	dal, steps := auditapp.WithStepTimes(ctx)
	out, err := s.base.AdmitRecordingSaveGroup(dal, in)
	s.request, s.accepted = in, out
	remaining := int64(-1)
	if until, ok := ctx.Deadline(); ok {
		remaining = time.Until(until).Milliseconds()
	}
	s.t.Logf("actual_request_sql_steps ctx_error=%v deadline_remaining_ms=%d steps=%s", ctx.Err(), remaining, steps.String())
	s.t.Logf("actual_request_sql_admission children=%d elapsed_ms=%d t0_age_ms=%d error=%v", len(in.Children), time.Since(began).Milliseconds(), time.Since(out.CreatedAt).Milliseconds(), err)
	return out, err
}

// This fixture already supplies synthetic identity/settings observations at
// source admission. Keep the same explicit boundary for the real request guard:
// it is a bounded configured policy, never a grant or a constant allow result.
type dispatchWorkflowApprovalSettings struct {
	policy    identity.Policy
	hardUntil time.Time
}

func (s dispatchWorkflowApprovalSettings) IdentityPolicy(ctx context.Context, issuer string) (identity.Policy, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if ctx == nil || ctx.Err() != nil || issuer != s.policy.Issuer || !now.Before(s.hardUntil) {
		return identity.Policy{}, identity.ErrDenied
	}
	p := s.policy
	p.ObservedAt = now
	p.FreshUntil = identity.Earlier(now.Add(5*time.Second), s.hardUntil)
	if end, ok := ctx.Deadline(); ok {
		p.FreshUntil = identity.Earlier(p.FreshUntil, end).UTC().Truncate(time.Microsecond)
	}
	if p.Validate(now) != nil {
		return identity.Policy{}, identity.ErrUnavailable
	}
	return p, nil
}

type dispatchWorkflowIdentity struct {
	who   identity.Identity
	until time.Time
}

func (r dispatchWorkflowIdentity) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	if ctx.Err() != nil || !time.Now().Before(r.until) {
		return identity.Identity{}, identity.ErrDenied
	}
	i := r.who
	i.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
	i.ValidUntil = r.until
	return i, nil
}

type dispatchWorkflowOperations struct {
	t                *testing.T
	service          *presentation.AuditedOperations
	identity         dispatchWorkflowIdentity
	lastID           string
	groupRequests    *dispatchGroupAdmissions
	originalOwnerEnd time.Time
	times            *dispatchPortTimes
}

func (s *dispatchWorkflowOperations) call(ctx context.Context, window time.Duration, preview, key string, continuation bool) (presentation.OperationReply, string, error) {
	s.t.Helper()
	s.times.reset()
	defer s.times.report(s.t)
	caller, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	s.originalOwnerEnd, _ = caller.Deadline()
	current, _, err := identities.NewBearerRequestWithin(caller, s.identity, "synthetic-workflow-token", time.Now, window)
	if err != nil {
		s.t.Fatal(err)
	}
	input, err := json.Marshal(struct {
		Preview  string `json:"preview_id"`
		Key      string `json:"idempotency_key"`
		Continue bool   `json:"continue_acquisition,omitempty"`
	}{preview, key, continuation})
	if err != nil {
		s.t.Fatal(err)
	}
	reply, err := s.service.Call(caller, current, "request_capture", input)
	return reply, s.lastID, err
}

// Consume only the already accepted normal/resolution backing. Unlike legacy
// audit helpers this does not provision a replacement pool or refill a quota.
func newDispatchWorkflowOperations(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, admissions *postgres.ContextAdmissions, intents auditapp.CaptureOperationPublication, workflow *manualSnapshotWorkflow, who identity.Identity, settings identity.Policy) *dispatchWorkflowOperations {
	t.Helper()
	profiles := f.readAuditProfiles(t)
	journalPool := f.fixturePool("operation_audit_runtime", "synthetic-operation-journal")
	ackPool := f.fixturePool("operation_audit_ack_runtime", "synthetic-operation-ack")
	gates := map[string]*auditapp.HealthyOperationAuditor{}
	material := f.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	for _, p := range []audit.OperationLifecyclePolicy{profiles.Normal.Policy, profiles.Resolution.Policy} {
		journal, err := postgres.NewHealthyOperationJournal(ctx, journalPool, p, policy.Scenario.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := postgres.NewOperationAcknowledgements(ctx, ackPool, p.RootID, p.Lane, policy.Scenario.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := postgres.NewOperationLifecycles(ctx, journalPool, p.RootID, p.Lane, policy.Scenario.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		closed, err := objectstore.NewClosedOperationAuditObjects(f.store, p.StoreID, f.keys, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		gate, err := auditapp.NewHealthyOperationAuditor(p, journal, ack, &objectstore.OperationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, closed, lifecycle, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		gates[p.Lane] = gate
	}
	previews, err := postgres.NewContextPreviews(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := postgres.NewContextStorageReader(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	groupRequests := &dispatchGroupAdmissions{t: t, base: admissions}
	times := &dispatchPortTimes{}
	hardUntil := time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	approvals := dispatchWorkflowApprovalSettings{policy: settings, hardUntil: hardUntil}
	if _, err := approvals.IdentityPolicy(ctx, policy.Authority.Creator.Issuer); err != nil {
		t.Fatal("bounded synthetic approval settings", err)
	}
	investigation := captureapp.ContextInvestigation{RootID: policy.Scenario.a.RootID, InstallationID: policy.Authority.InstallationID, Previews: previews, Replay: admissions, Admission: admissions, Targets: workflow.Facts, Eligibility: dispatchTimedEligibility{base: workflow.Eligibility, times: times}, Capabilities: workflow.Facts, Retention: workflow.Retention, Storage: storage, Processing: processing, Recovery: dispatchTimedRecovery{base: policy.Scenario.recovery.reader, times: times}, PolicyAccepted: policy.Reader, RecordingSources: previews, RecordingGroups: groupRequests, RecordingPolicies: captureapp.CurrentRecordingPolicies{Documents: dispatchPolicyDocuments{policy}, Accepted: policy.Reader, CompileRecorder: policySourceCompile(pcap.NewCompiler()), RecipeName: planningapp.ContextRecipeName, RecipeDigest: planningapp.RecipeDigest(), Now: time.Now}, Approvals: dispatchTimedApprovals{base: approvals, times: times}, RecordingSaveEnabled: true, Lifetime: time.Minute, Now: time.Now, NewID: custodyID}
	submission := captureapp.ContextSubmission{ContextInvestigation: investigation, Intents: intents, Start: workflow}
	reads, err := postgres.NewContextProgressReads(ctx, f.roles["hub-runtime"], investigation.RootID, policy.Scenario.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	progress := captureapp.ContextProgressService{RootID: investigation.RootID, InstallationID: investigation.InstallationID, Reader: reads, Recovery: investigation.Recovery, Now: time.Now}
	captures, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: "https://workflow.fixture.invalid", CollectionEnabled: true, Now: time.Now, NewID: custodyID}, submission, progress)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := presentation.NewInvestigationOperations(captures, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := &dispatchWorkflowOperations{t: t, identity: dispatchWorkflowIdentity{who: who, until: hardUntil}, groupRequests: groupRequests, times: times}
	out.service, err = presentation.NewHealthyAuditedOperations(presentation.AuditedOperationsConfig{RootID: investigation.RootID, Retention: time.Duration(profiles.Normal.RetainedSeconds) * time.Second, NormalConcurrency: 1, ResolutionConcurrency: 1, PerPrincipalConcurrency: 1, NormalPerSecond: 100, ResolutionPerSecond: 100, Now: time.Now, NewID: func() string { out.lastID = custodyID(); return out.lastID }}, inner, gates["normal"], gates["resolution"], mac)
	if err != nil {
		t.Fatal(err)
	}
	out.service.Timing = func(event, timing string) { t.Logf("actual_public_audit_timing event=%s %s", event, timing) }
	return out
}

func dispatchWorkflowEnvelope(t *testing.T, reply presentation.OperationReply, expected string) json.RawMessage {
	t.Helper()
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(reply.Body, &envelope); err != nil || envelope.Status != expected {
		t.Fatalf("unexpected actual public workflow response status=%s error=%v body=%s", envelope.Status, err, reply.Body)
	}
	return envelope.Data
}

// Failure-only readback runs after the real Continue has returned. It adds no
// SQL work to a successful dispatch or to any child acquisition interval.
func logDispatchWorkflowFailure(t *testing.T, ctx context.Context, f *capacitySQLFixture, parent string) {
	t.Helper()
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var rows []byte
	err := f.admin.QueryRow(call, `SELECT coalesce(jsonb_agg(jsonb_build_object(
 'child',c.id,'ordinal',c.group_ordinal,'state',c.state,'createdAt',c.created_at,
 'startBy',convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}',
 'processingUntil',convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Snapshot,ProcessingUntil}',
 'executionPhase',e.phase,'auditRequestUntil',a.request_until,'auditWriteUntil',a.write_until,
 'intentStarted',a.intent_started,'intentAcknowledgedAt',c.intent_acknowledged_at
 ) ORDER BY c.group_ordinal),'[]'::jsonb)::text
 FROM context_capture c LEFT JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id
 LEFT JOIN operation_audit a ON a.root_id=c.root_id AND a.id=c.intent_operation_id
 WHERE c.group_id=$1`, parent).Scan(&rows)
	if err != nil {
		t.Logf("workflow_failure_deadline_readback_error=%v", err)
		return
	}
	t.Logf("workflow_failure_stored_child_deadlines=%s", rows)
}

func qualifyManualRecordingSaveDispatch(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, ledger *postgres.PolicySources, original captureapp.PolicySourceAdmission, refresh func(*testing.T) captureapp.PolicySourceCheck, intents auditapp.CaptureOperationPublication, requestModes ...bool) {
	t.Helper()
	requestMode := len(requestModes) > 0 && requestModes[0]
	count := policy.Compiled.IncidentPods
	if count != 2 && count != 16 {
		t.Fatal("workflow qualifier requires independently configured N2 or N16")
	}
	began := time.Now()
	var keyServices *contextKeyUnwrapServices
	if requestMode {
		// Real long-lived verifier services exist before the request's final facts.
		// Every child still supplies its own fresh peer, binding and bounded controls.
		keyServices = newContextKeyUnwrapServices(t, ctx, f.admin, f.fixturePool, policy.Scenario.a.RootID, policy.Authority.InstallationID)
	}
	sources := []captureapp.PolicySourceAdmission{original}
	checks := []captureapp.PolicySourceCheck{refresh(t)}
	for n := 1; n < count; n++ {
		check := refresh(t)
		check.SourceID, check.Fence = custodyID(), custodyID()
		check.Target.Request.PodUID = custodyID()
		if count == 2 {
			check.Target.Request.PodName += "-workflow-second"
		} else {
			check.Target.Request.PodName += fmt.Sprintf("-workflow-%d", n)
		}
		check.Target.Pin.UID, check.Target.Pin.Name = check.Target.Request.PodUID, check.Target.Request.PodName
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
		second, err := ledger.AdmitSource(ctx, check)
		if err != nil {
			t.Fatal("real additional source", n, err)
		}
		sources = append(sources, second)
		checks = append(checks, check)
	}
	maximum := min(policy.Compiled.Recorder.Action.MaxBytes, int64(artifact.RecordingNativeLimit))
	authorities, err := postgres.NewAutomationAuthorities(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID, policy.Authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := postgres.NewContextStorageReader(ctx, f.roles["hub-runtime"], policy.Scenario.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	retainedReader := privacyapp.AcceptedRetentionReader{Topology: policy.Scenario.retention.topology, Sources: policy.Scenario.retention.reader, Now: time.Now}
	readers := &manualRecordingSaveReaders{Current: authorities, Storage: storage, Retention: &retainedReader}
	prepare := func() (value.RecordingSaveGroupAdmission, []policySourceSnapshotAdmissionFixture) {
		var err error
		readers.Sources, err = ledger.ListSources(ctx, policy.Authority.PolicyUID)
		if err != nil || len(readers.Sources) != count {
			t.Fatal("exact bounded source set", err, len(readers.Sources))
		}
		// One common current controller refresh per cohort; each target still reads
		// its own real SQL permission, retention and storage facts.
		common := refresh(t)
		parts := make([]policySourceSnapshotAdmissionFixture, count)
		for n, source := range sources {
			current := common
			current.SourceID, current.Fence = source.Permit.Binding.SourceID, source.Permit.Binding.Fence
			current.Initial = false
			current.ExpectedCredit = source.Permit.Credit
			current.Target = checks[n].Target
			current.Target.ObservedAt, current.Target.FreshUntil = current.ObservedAt, current.ValidUntil
			current.Node.PodUID = current.Target.Request.PodUID
			current.Retention = privacy.Resolution{}
			parts[n] = prepareManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], policy, source, current, maximum, readers)
		}
		return prepareManualRecordingSaveGroup(t, ctx, f, policy, parts)
	}
	// Initial metadata templates configure the real service before a request.
	// They create no preview row, reservation, accepted capture or native keys.
	_, parts := prepare()
	workflow := newManualSnapshotWorkflow(t, ctx, f, policy, parts)
	workflow.KeyServices = keyServices
	operations := newDispatchWorkflowOperations(t, ctx, f, policy, admissions, intents, workflow, parts[0].Admission.RecordingSave.Initiator.VerifiedIdentity, checks[0].Settings)
	var shortID string
	if !t.Run("legacy-five-second-normal-audit-downgrade", func(t *testing.T) {
		before := readManualSaveCounters(t, ctx, f, policy)
		reply, id, err := operations.call(ctx, 5*time.Second, custodyID(), "missing-reviewed-preview", false)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(reply.Body)
		dispatchWorkflowEnvelope(t, reply, "error")
		shortID = id
		if readManualSaveCounters(t, ctx, f, policy) != before {
			t.Fatal("missingpreview audit changedcollectionspend")
		}
		qualifyRecordingSaveDispatchLegacyDowngrade(t, ctx, f.admin, shortID)
	}) {
		return
	}
	if requestMode && !t.Run("empty-group112-down-up-before-request", func(t *testing.T) { qualifyRecordingSaveGroupBoundsEmptyDownUp(t, ctx, f.admin) }) {
		return
	}
	// The real positive request starts only after setup and the compatible audit.
	// This is a new reviewed parent; no old preview/capture or first proof is renewed.
	preparedAt := time.Now()
	group, parts := prepare()
	previews, err := postgres.NewContextPreviews(ctx, f.roles["hub-runtime"], group.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateRecordingGroupPreview(ctx, group.Preview); err != nil {
		t.Fatal(err)
	}
	t.Logf("workflow_sources=%d setup_ms=%d final_preparation_ms=%d original_first_proof_remaining_ms=%d", count, time.Since(began).Milliseconds(), time.Since(preparedAt).Milliseconds(), time.Until(manualGroupProofDeadline(group)).Milliseconds())
	before := readManualSaveCounters(t, ctx, f, policy)
	var accepted value.Accepted
	var longID string
	submissionCase := "real-sql-admission-to-queued-group-workflow"
	if requestMode {
		submissionCase = "real-one-owner-request-admission-to-queued-group-workflow"
	}
	if !t.Run(submissionCase, func(t *testing.T) {
		if !requestMode {
			call, end := context.WithDeadline(ctx, manualGroupProofDeadline(group))
			admittedAt := time.Now()
			accepted, err = admissions.AdmitRecordingSaveGroup(call, group)
			end()
			if err != nil || accepted.Group == nil || len(accepted.Group.Children) != count {
				t.Fatal("real positive group admission", err)
			}
			t.Logf("workflow_sources=%d admission_ms=%d actual_t0_age_at_return_ms=%d original_startby_remaining_ms=%d", count, time.Since(admittedAt).Milliseconds(), time.Since(accepted.CreatedAt).Milliseconds(), time.Until(accepted.Group.Children[0].Expectation.Snapshot.StartBy).Milliseconds())
		}
		// The new Request owns REALSQLadmission and all starts under one owner;
		// legacy Continue keeps its original separate accepted-only qualification.
		started := time.Now()
		reply, id, err := operations.call(ctx, identity.RecordingSaveRequestWindow, group.Preview.ID, group.IdempotencyKey, !requestMode)
		if requestMode {
			accepted = operations.groupRequests.accepted
		}
		longID = id
		var response struct {
			Status string `json:"status"`
		}
		if err != nil || json.Unmarshal(reply.Body, &response) != nil || response.Status != "ok" {
			logDispatchWorkflowFailure(t, ctx, f, group.Preview.CaptureID)
		}
		if err != nil {
			t.Fatal("actual audited Continue", err)
		}
		defer clear(reply.Body)
		data := dispatchWorkflowEnvelope(t, reply, "ok")
		var receipt struct {
			CaptureID string `json:"capture_id"`
			Phase     string `json:"phase"`
		}
		if json.Unmarshal(data, &receipt) != nil || receipt.CaptureID != accepted.CaptureID || receipt.Phase != "Accepted" {
			t.Fatal("actual workflow changed parent receipt", string(data))
		}
		if accepted.Group == nil || len(accepted.Group.Children) != count {
			t.Fatal("real request did not admit exact complete group")
		}
		if requestMode {
			original := operations.groupRequests.request.RequestBounds
			if operations.groupRequests.calls != 1 || original == nil || original.Requester != group.Preview.Actor || original.Until.After(operations.originalOwnerEnd) {
				t.Fatal("original request provenance changed across actualSQLadmission")
			}
			for _, child := range accepted.Group.Children {
				if child.Expectation.Snapshot.StartBy.After(original.Until) {
					t.Fatal("snapshot exceeds original request owner")
				}
			}
		}
		earliest := accepted.Group.Children[0].Expectation.Snapshot.StartBy
		var executions int
		if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM context_execution e JOIN context_capture c ON c.id=e.capture_id AND c.root_id=e.root_id WHERE c.group_id=$1 AND e.phase='started'`, accepted.CaptureID).Scan(&executions); err != nil || executions != count {
			t.Fatal("real runner did not start all admitted children", executions, err)
		}
		t.Logf("workflow_sources=%d actual_normal_audit_plus_continue_ms=%d original_t0_age_after_queue_ms=%d original_startby_remaining_ms=%d; real SQL/runner/producer/holder/nodequeue, in-process local attestations synthetic", count, time.Since(started).Milliseconds(), time.Since(accepted.CreatedAt).Milliseconds(), time.Until(earliest).Milliseconds())
	}) {
		return
	}
	if !t.Run("normal-fifteen-second-audit-populated111-refusal", func(t *testing.T) {
		var created, until time.Time
		var actualRoot, format string
		if err = f.admin.QueryRow(ctx, `SELECT root_id::text,intent->>'InputFormat',(intent->>'CreatedAt')::timestamptz,request_until FROM operation_audit WHERE id=$1 AND lane='normal' AND intent->>'Name'='request_capture'`, longID).Scan(&actualRoot, &format, &created, &until); err != nil || actualRoot != group.RootID || format != "context-input/v1" || !until.After(created.Add(5*time.Second)) || until.After(created.Add(identity.RecordingSaveRequestWindow)) {
			t.Fatal("real public invocation did not persist its prospective15s window", err, until.Sub(created))
		}
		qualifyRecordingSaveDispatchPopulatedDowngrade(t, ctx, f.admin, longID, shortID)
	}) {
		return
	}
	if requestMode && !t.Run("populated-group112-downgrade-refusal", func(t *testing.T) {
		qualifyRecordingSaveGroupBoundsPopulatedDowngrade(t, ctx, f.admin, accepted.CaptureID)
	}) {
		return
	}
	for n := range parts {
		parts[n].Accepted = accepted.Group.Children[n]
		if requestMode {
			parts[n].Admission.Plan, parts[n].Admission.Registration, err = planningapp.ReanchorRecordingSaveGroup(parts[n].Admission.Plan, parts[n].Admission.Registration, accepted.CreatedAt, policy.Authority.NotAfter, *operations.groupRequests.request.RequestBounds)
		} else {
			parts[n].Admission.Plan, parts[n].Admission.Registration, err = planningapp.ReanchorRecordingSave(parts[n].Admission.Plan, parts[n].Admission.Registration, accepted.CreatedAt, policy.Authority.NotAfter)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !parts[n].Admission.Plan.Input.Snapshot.Request.Equal(*parts[n].Accepted.Expectation.Snapshot) {
			t.Fatal("fixture reanchor changed original accepted snapshot")
		}
	}
	persistHistory := func() bool {
		return t.Run("one-encrypted-parent-history-fresh-selection-settings", func(t *testing.T) {
			who, err := operations.identity.Resolve(ctx, "synthetic-workflow-token")
			if err != nil {
				t.Fatal(err)
			}
			qualifyManualRecordingSaveGroupHistory(t, ctx, f, policy, group.Preview, accepted, who)
		})
	}
	// History describes genuine accepted work, not completed evidence. Save it
	// while its original write interval is live, after every mandatory start.
	if requestMode && !persistHistory() {
		return
	}
	for n, part := range parts {
		if !t.Run(fmt.Sprintf("native-child-%d", n), func(t *testing.T) { workflow.Complete(t, ctx, part) }) {
			return
		}
	}
	if !t.Run("passive-replay-keeps-shared-t0-and-spend", func(t *testing.T) {
		after := readManualSaveCounters(t, ctx, f, policy)
		if after.Executions != before.Executions+1 || after.Collected != before.Collected+int64(count)*maximum || after.Occurrences != before.Occurrences || after.Observed != before.Observed || after.Shares != before.Shares || after.Reservations != before.Reservations+count {
			t.Fatal("real workflow changed accepted resource units", before, after)
		}
		var original []byte
		if err = f.admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(c.id,c.created_at,c.expectation_json,e.attempt_id,e.binding_json,e.phase) ORDER BY c.group_ordinal)::text FROM context_capture c JOIN context_execution e ON e.capture_id=c.id AND e.root_id=c.root_id WHERE c.group_id=$1`, accepted.CaptureID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		reply, _, err := operations.call(ctx, identity.RecordingSaveRequestWindow, group.Preview.ID, group.IdempotencyKey, false)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(reply.Body)
		data := dispatchWorkflowEnvelope(t, reply, "ok")
		var receipt struct {
			CaptureID string `json:"capture_id"`
		}
		if json.Unmarshal(data, &receipt) != nil || receipt.CaptureID != accepted.CaptureID {
			t.Fatal("passive replay replaced parent")
		}
		var replayed []byte
		if err = f.admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(c.id,c.created_at,c.expectation_json,e.attempt_id,e.binding_json,e.phase) ORDER BY c.group_ordinal)::text FROM context_capture c JOIN context_execution e ON e.capture_id=c.id AND e.root_id=c.root_id WHERE c.group_id=$1`, accepted.CaptureID).Scan(&replayed); err != nil || !bytes.Equal(original, replayed) || readManualSaveCounters(t, ctx, f, policy) != after {
			t.Fatal("passive public replay changed real execution/time/spend", err)
		}
		for _, child := range accepted.Group.Children {
			if !child.CreatedAt.Equal(accepted.CreatedAt) || !child.Expectation.Snapshot.T0.Equal(accepted.CreatedAt) {
				t.Fatal("group child shifted original SQL t0")
			}
		}
	}) {
		return
	}
	if !requestMode {
		persistHistory()
	}
}
