//go:build cgo && libpcap

package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Only process/target/capability/local-start and packet inputs are synthetic.
// All admitted work, execution transitions, retention and encrypted output use
// the real adapters. No fake Start acknowledgment or native provider is used.
type manualSnapshotWorkflow struct {
	Facts       *manualSnapshotWorkflowFacts
	Runner      executionapp.APIContextRunner
	Executions  *postgres.APIContextExecutions
	Eligibility authapp.CaptureEligibility
	Retention   privacyapp.RetentionResolver
	t           *testing.T
	f           *capacitySQLFixture
	policy      policySourceAcceptedFixture
	mu          sync.Mutex
	nodes       map[manualSnapshotNodeKey]*manualSnapshotNode
	stages      map[string]*sourceSnapshotCompletionState
}
type manualSnapshotNodeKey struct{ NodeUID, BootID, PodUID, Epoch string }

func manualSnapshotKey(b collector.SourceBinding) manualSnapshotNodeKey {
	return manualSnapshotNodeKey{b.NodeUID, b.BootID, b.CollectorPodUID, b.CollectorEpoch}
}

type manualSnapshotNode struct {
	channel *delivery.NodeChannel
	peer    delivery.NodePeer
	holder  *bootstrap.ConnectorRecordings
	after   uint64
}
type manualSnapshotWorkflowFacts struct {
	parts   []policySourceSnapshotAdmissionFixture
	process value.APIProcessBinding
}

func workflowNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
func newManualSnapshotWorkflow(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, parts []policySourceSnapshotAdmissionFixture) *manualSnapshotWorkflow {
	t.Helper()
	if len(parts) == 0 {
		t.Fatal("workflow has no retained sources")
	}
	first := parts[0]
	process := value.APIProcessBinding{InstallationID: policy.Authority.InstallationID, ClusterID: policy.Authority.ClusterID, IssuerEpoch: first.Admission.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: first.Admission.Plan.Input.Capability.CollectorImageDigest}
	facts := &manualSnapshotWorkflowFacts{parts: parts, process: process}
	guards := postgres.EffectTransactionGuards{Recovery: policy.Scenario.recovery.guard, Retention: policy.Scenario.retention.guard}
	executions, err := postgres.NewAPIContextExecutions(ctx, f.roles["hub-runtime"], first.Admission.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	current, err := postgres.NewAutomationAuthorities(ctx, f.roles["hub-runtime"], first.Admission.RootID, policy.Authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := authapp.CaptureEligibility{Human: authapp.Evaluator{Permissions: policy.Scenario.p, Now: workflowNow}, Accepted: policy.Sources, Current: current, Now: workflowNow}
	retention := privacyapp.RetentionResolver{Policies: manualWorkflowRetention{policy.Scenario.retention}, RetainedPolicies: manualGroupRetainedPolicies{policy.Scenario.retention}, Now: workflowNow}
	w := &manualSnapshotWorkflow{Facts: facts, Executions: executions, Eligibility: eligibility, Retention: retention, t: t, f: f, policy: policy, nodes: map[manualSnapshotNodeKey]*manualSnapshotNode{}, stages: map[string]*sourceSnapshotCompletionState{}}
	local := &manualWorkflowStarts{objects: map[string]value.PreparedStart{}, bindings: map[string]value.Binding{}, committed: map[string]value.Disposition{}}
	w.Runner = executionapp.APIContextRunner{Read: executions, Prepare: executions, Record: executions, Process: facts, Local: local, Starts: local, Targets: facts, Eligibility: eligibility, Capabilities: facts, Retention: retention, Recovery: policy.Scenario.recovery.reader, Output: w, Collector: manualWorkflowNoCapture{}, Now: workflowNow}
	for _, part := range parts {
		b := part.Source.Binding
		if _, ok := w.nodes[manualSnapshotKey(b)]; ok {
			continue
		}
		channel, err := delivery.NewNodeChannel(policyObservationNode{collector.Identity{NodeName: "worker", NodeUID: b.NodeUID, PodUID: b.CollectorPodUID, BootID: b.BootID}}, policyObservationNodeIssuer{}, workflowNow, nil)
		if err != nil {
			t.Fatal(err)
		}
		der, _, _, err := channel.Enroll(ctx, "synthetic-component", []byte("synthetic-token"), []byte("synthetic-csr"), b.BootID, b.CollectorEpoch)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := channel.Peer(sha256.Sum256(der))
		if err != nil {
			t.Fatal(err)
		}
		if err = channel.Report(peer, b.CollectorEpoch, collector.Report{Sequence: 1, ObservedAt: workflowNow(), Facts: collector.Facts{Kernel: collector.KernelVersion{Major: 6, Minor: 8}}, Mechanisms: []collector.Availability{{Mechanism: collector.MechanismPacket, Prerequisites: true, Adapter: collector.AdapterAvailable, Hook: collector.HookTC}}}); err != nil {
			t.Fatal(err)
		}
		holder := bootstrap.NewConnectorRecordings(channel, nil, workflowNow, func(line string) { t.Log(line) })
		channel.SetPacketSink(holder)
		w.nodes[manualSnapshotKey(b)] = &manualSnapshotNode{channel: channel, peer: peer, holder: holder}
	}
	t.Cleanup(func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, s := range w.stages {
			if s.Close != nil {
				s.Close()
			}
		}
		// Delivery/StoreSnapshot is synchronous in this fixture: all producer
		// calls have returned before cleanup. No consumer or writer goroutine
		// outlives the test. Drop shared node/holder references after children.
		for _, node := range w.nodes {
			node.channel.SetPacketSink(nil)
		}
		w.stages, w.nodes = nil, nil
	})
	return w
}
func (w *manualSnapshotWorkflow) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	result, err := w.Runner.Execute(ctx, current, id)
	if err != nil {
		return err
	}
	if result.State != "Recording" {
		return fmt.Errorf("real runner did not queue: %s", result.State)
	}
	recovery, err := w.policy.Scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		return err
	}
	_, execution, err := w.Executions.ReadRecordingWork(ctx, id, recovery)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	stage := w.stages[id]
	if stage == nil || stage.Work.Snapshot == nil {
		return fmt.Errorf("runner returned without actual node work")
	}
	stage.Execution = execution
	return nil
}
func (w *manualSnapshotWorkflow) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	if e.Snapshot == nil {
		return nil, value.ErrInvalid
	}
	part, ok := w.Facts.part(e.Snapshot.SourceID)
	if !ok {
		return nil, value.ErrDenied
	}
	bound, err := w.f.store.ForCustody(e.Registration.StoreID)
	if err != nil {
		return nil, err
	}
	node := w.nodes[manualSnapshotKey(part.Source.Binding)]
	if node == nil {
		return nil, value.ErrUnavailable
	}
	var before int64
	if err = w.f.admin.QueryRow(ctx, `SELECT observed_bytes_spent FROM policy_acceptance WHERE root_id=$1 AND id=$2`, part.Admission.RootID, part.Source.Binding.AcceptanceID).Scan(&before); err != nil {
		return nil, err
	}
	producer, err := objectstore.NewArtifactProducer(bound, w.f.keys, recordingJournal{}, workflowNow)
	if err != nil {
		return nil, err
	}
	artifactOutput, err := producer.Prepare(ctx, e, "")
	if err != nil {
		return nil, err
	}
	output := node.holder.Prepare(artifactOutput, e)
	stage := &sourceSnapshotCompletionState{ObservationBefore: before, Executions: w.Executions, Process: w.Facts.process, Bound: bound, Channel: node.channel, Peer: node.peer, Holder: node.holder, Close: output.Close}
	w.mu.Lock()
	w.stages[e.CaptureUID] = stage
	w.mu.Unlock()
	return &manualWorkflowPrepared{PreparedContext: output, recorder: output, node: node, stage: stage}, nil
}

type manualWorkflowPrepared struct {
	evidence.PreparedContext
	recorder evidence.SourceSnapshotRecorder
	node     *manualSnapshotNode
	stage    *sourceSnapshotCompletionState
}

func (p *manualWorkflowPrepared) StartSourceSnapshot(ctx context.Context, x collector.SourceSnapshot) (time.Time, error) {
	queued, err := p.recorder.StartSourceSnapshot(ctx, x)
	if err != nil {
		return queued, err
	}
	work, err := p.node.channel.Poll(ctx, p.node.peer, x.Binding.CollectorEpoch, p.node.after, 0)
	if err != nil {
		return time.Time{}, err
	}
	if len(work) != 1 || work[0].Snapshot == nil || !work[0].Snapshot.Equal(x) {
		return time.Time{}, fmt.Errorf("node did not consume exact snapshot")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || work[0].NotAfter.After(deadline) || work[0].NotAfter.After(x.Request.StartBy) || !workflowNow().Before(work[0].NotAfter) {
		return time.Time{}, fmt.Errorf("node work exceeded original start/request bound")
	}
	p.node.after = work[0].Sequence
	p.stage.Work = work[0]
	return queued, nil
}
func (w *manualSnapshotWorkflow) Complete(t *testing.T, ctx context.Context, part policySourceSnapshotAdmissionFixture) {
	t.Helper()
	w.mu.Lock()
	stage := w.stages[part.Accepted.CaptureID]
	w.mu.Unlock()
	if stage == nil {
		t.Fatal("no real started child", part.Accepted.CaptureID)
	}
	stage.RecordStored = func(ctx context.Context, c evidence.RecordingCollection, _ artifact.SourceSnapshotOutcome) (value.APIExecution, error) {
		recovery, err := w.policy.Scenario.recovery.reader.RecoveryState(ctx)
		if err != nil {
			return value.APIExecution{}, err
		}
		work, started, err := w.Executions.ReadRecordingWork(ctx, part.Accepted.CaptureID, recovery)
		if err != nil {
			return value.APIExecution{}, err
		}
		result, err := w.Runner.CollectRecording(ctx, work, started, manualWorkflowCollect{stage.Holder, fleet.APIContextWork{CaptureID: part.Accepted.CaptureID, AttemptID: part.Accepted.Expectation.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(part.Accepted.Expectation)}})
		if err != nil {
			return value.APIExecution{}, err
		}
		if result.State != "StoredPendingVerification" || result.Copies != c.Completion.Copies {
			return value.APIExecution{}, fmt.Errorf("real runner did not commit joined completion: %s", result.State)
		}
		started.Phase, started.AcquiredAt, started.CompletedAt, started.Copies = "stored", c.Acquired, c.Completion.StoredAt, c.Completion.Copies
		return started, nil
	}
	completeSourceSnapshotCompletion(t, ctx, w.f, w.policy, part, stage)
}

type manualWorkflowCollect struct {
	holder *bootstrap.ConnectorRecordings
	work   fleet.APIContextWork
}

func (c manualWorkflowCollect) CollectRecording(context.Context) (evidence.RecordingCollection, error) {
	return c.holder.Collect(c.work)
}

type manualWorkflowNoCapture struct{}

func (manualWorkflowNoCapture) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	return nil, value.ErrUnavailable
}

type manualWorkflowRetention struct{ f *retentionEffectFixture }

func (r manualWorkflowRetention) RetentionPolicies(ctx context.Context, target authorization.Target) (privacy.PolicySet, error) {
	return manualGroupRetentionPolicies(ctx, r.f, target)
}
func (f *manualSnapshotWorkflowFacts) part(id string) (policySourceSnapshotAdmissionFixture, bool) {
	for _, p := range f.parts {
		if p.Source.Binding.SourceID == id {
			return p, true
		}
	}
	return policySourceSnapshotAdmissionFixture{}, false
}
func (f *manualSnapshotWorkflowFacts) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return value.APIProcessObservation{}, err
	}
	now := workflowNow()
	return value.APIProcessObservation{Binding: f.process, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}
func (f *manualSnapshotWorkflowFacts) ResolveSourceSnapshot(ctx context.Context, target targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error) {
	p, ok := f.part(target.SourceID)
	if !ok || p.Admission.Plan.Input.SnapshotSource == nil {
		return targets.SourceSnapshotResolution{}, value.ErrDenied
	}
	original := *p.Admission.Plan.Input.SnapshotSource
	if original.Original != target {
		return targets.SourceSnapshotResolution{}, value.ErrDenied
	}
	if ctx.Err() != nil {
		return targets.SourceSnapshotResolution{}, ctx.Err()
	}
	now := workflowNow()
	if !now.Before(original.State.LeafUntil) {
		return targets.SourceSnapshotResolution{}, value.ErrExpired
	}
	original.ObservedAt, original.FreshUntil = now, now.Add(5*time.Second)
	original.Process.ObservedAt, original.Process.FreshUntil = now, original.FreshUntil
	original.ReportedAt, original.ReportFreshUntil = now, now.Add(15*time.Second)
	original.State.ObservedAt, original.State.FreshUntil = original.ReportedAt, original.ReportFreshUntil
	return original, nil
}
func (f *manualSnapshotWorkflowFacts) ResolveSourceSnapshots(ctx context.Context, in []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error) {
	if len(in) == 0 || len(in) > 16 {
		return nil, value.ErrInvalid
	}
	out := make([]targets.SourceSnapshotResolution, len(in))
	for i, t := range in {
		var err error
		out[i], err = f.ResolveSourceSnapshot(ctx, t)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (f *manualSnapshotWorkflowFacts) ResolvePod(context.Context, targets.Request) (targets.PodResolution, error) {
	return targets.PodResolution{}, value.ErrUnavailable
}
func (f *manualSnapshotWorkflowFacts) ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error) {
	return targets.PodResolution{}, value.ErrUnavailable
}
func (f *manualSnapshotWorkflowFacts) ResolveWorkloadIdentity(ctx context.Context, r targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error) {
	p := f.parts[0].Source.Target.Request
	if ctx.Err() != nil {
		return targets.WorkloadIdentityResolution{}, ctx.Err()
	}
	if r.ClusterID != p.ClusterID || r.Namespace != p.Namespace.Name || r.Kind != p.Workload.Kind || r.Name != p.Workload.Name {
		return targets.WorkloadIdentityResolution{}, value.ErrDenied
	}
	now := workflowNow()
	return targets.WorkloadIdentityResolution{Reference: r, ClusterID: p.ClusterID, Namespace: p.Namespace, Workload: p.Workload, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (f *manualSnapshotWorkflowFacts) ContextCapability(ctx context.Context, target authorization.Target) (planvalue.ContextCapability, error) {
	for _, p := range f.parts {
		if p.Admission.Eligibility.Target == target {
			c := p.Admission.Plan.Input.Capability
			now := workflowNow()
			c.ObservedAt, c.FreshUntil = now, now.Add(5*time.Second)
			return c, ctx.Err()
		}
	}
	return planvalue.ContextCapability{}, value.ErrDenied
}

// Explicit synthetic local CapacityReservation attestation. The one-use map
// models original object identity/CAS only; it supplies no SQL capture authority.
type manualWorkflowStarts struct {
	mu        sync.Mutex
	objects   map[string]value.PreparedStart
	bindings  map[string]value.Binding
	committed map[string]value.Disposition
}

func (s *manualWorkflowStarts) PrepareStart(ctx context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return value.PreparedStart{}, ctx.Err()
	}
	if !c.Valid(workflowNow()) {
		return value.PreparedStart{}, value.ErrExpired
	}
	id := c.Binding.CaptureID
	if old, ok := s.objects[id]; ok {
		if s.bindings[id] != c.Binding {
			return value.PreparedStart{}, value.ErrConflict
		}
		return old, nil
	}
	if !c.MayCreate {
		return value.PreparedStart{}, value.ErrDenied
	}
	out := value.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"}
	s.objects[id], s.bindings[id] = out, c.Binding
	return out, nil
}
func (s *manualWorkflowStarts) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookup(ctx, r)
}
func (s *manualWorkflowStarts) LookupStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	return s.ReadyStart(ctx, r)
}
func (s *manualWorkflowStarts) lookup(ctx context.Context, r value.Request) (value.Disposition, error) {
	if ctx.Err() != nil {
		return value.Disposition{}, ctx.Err()
	}
	if err := r.Validate(workflowNow()); err != nil {
		return value.Disposition{}, err
	}
	if s.bindings[r.Binding.CaptureID] != r.Binding || s.objects[r.Binding.CaptureID].ObjectUID != r.ObjectUID {
		return value.Disposition{}, value.ErrConflict
	}
	if old, ok := s.committed[r.Binding.CaptureID]; ok {
		old.MayStart = false
		return old, nil
	}
	return value.Disposition{ObjectUID: r.ObjectUID, ResourceVersion: "1", Phase: value.Ready, ValidUntil: r.ValidUntil}, nil
}
func (s *manualWorkflowStarts) ConsumeStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.lookup(ctx, r)
	if err != nil || old.Phase == value.StartCommitted {
		return old, err
	}
	out := value.Disposition{ObjectUID: r.ObjectUID, ResourceVersion: "2", Phase: value.StartCommitted, CommittedAt: workflowNow(), MayStart: true, ValidUntil: r.ValidUntil}
	s.committed[r.Binding.CaptureID] = out
	return out, nil
}
