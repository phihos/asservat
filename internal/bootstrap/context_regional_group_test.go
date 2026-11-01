package bootstrap

import (
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	deliveryapp "asservat.local/asservat/internal/application/delivery"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

// Synthetic current authority/SQL and regional replies; the hub runner, typed
// operations and Router are real. No provider, native packet or SQL claim.
type groupRegionalFixture struct {
	router           *contextstart.Router
	capacityRefusals int

	complete                            bool
	human                               identity.Identity
	authority                           authorization.AcceptedPolicyAuthority
	parent                              capturevalue.Accepted
	intents                             map[string]auditvalue.CaptureIntent
	mu                                  sync.Mutex
	ackActive, ackMaximum               atomic.Int64
	ackBlocked, releaseACK, firstQueued chan struct{}
	queued                              map[string]bool
	records                             map[string]execution.APIExecution
	methods                             map[string]int
	active, maximum                     atomic.Int64

	*regionalObservationFixture
	capability     planning.ContextCapability
	works          []executionapp.APIContextWork
	scopes         []*planning.SourceSnapshotContext
	retentionByPod map[string]privacy.Resolution
	resolved       targets.SourceSnapshotResolution
}

func (f *groupRegionalFixture) ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error) {
	return f.capability, nil
}
func (f *groupRegionalFixture) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	who, err := current.ResolveIdentity(ctx)
	if err != nil {
		return authorization.CaptureEligibility{}
	}
	return authorization.CaptureEligibility{Result: authorization.Result{Eligible: true, Principal: who.Principal, IdentityRevision: who.Policy, PermissionRevision: f.identity.Policy, ValidUntil: who.ValidUntil}, Target: target, VerifiedIdentity: who, DefaultAudience: f.work.Accepted.Expectation.Audience}
}

type groupRegionalRetention struct{ f *groupRegionalFixture }

func (r groupRegionalRetention) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	return r.f.retentionByPod[in.Target.PodUID], ctx.Err()
}

type groupRegionalStream struct {
	*regionalObservationStream
	group *groupRegionalFixture
}

func (s *groupRegionalStream) Send(ctx context.Context, frame contracts.APIContextFrame) error {
	if frame.Kind != contracts.APIContextOperationRequestFrame {
		return s.regionalObservationStream.Send(ctx, frame)
	}
	op, err := contracts.DecodeAPIContextOperation(frame.Payload)
	if err != nil {
		return err
	}
	if s.group.complete {
		f := s.group
		f.methods[op.Method]++
		// Every real control operation consumes a small, cancellation-bound delay;
		// this is deliberately not an immediate StartContext success fake.
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		var body any
		handled := true
		switch op.Method {
		case "prepare-output":
			var e artifact.ContextExpectation
			if json.Unmarshal(op.Body, &e) != nil || evidence.ContextExpectationDigest(e) != evidence.ContextExpectationDigest(f.work.Accepted.Expectation) {
				return execution.ErrConflict
			}
		case "prepare-start":
			body = execution.PreparedStart{ObjectUID: f.work.Accepted.Expectation.Registration.Location.AttemptID, ResourceVersion: "1"}
		case "ready-start", "consume-start":
			var request execution.Request
			if json.Unmarshal(op.Body, &request) != nil || request.Validate(time.Now()) != nil {
				return execution.ErrDenied
			}
			body = execution.Disposition{ObjectUID: request.ObjectUID, ResourceVersion: "1", Phase: execution.Ready, ValidUntil: request.ValidUntil}
			if op.Method == "consume-start" {
				v := body.(execution.Disposition)
				v.Phase = execution.StartCommitted
				v.MayStart = true
				v.CommittedAt = time.Now().UTC().Truncate(time.Microsecond)
				body = v
			}
		case "start-source-snapshot":
			if extra, err := f.router.Attach(ctx, f.work.Target.ClusterID, regionalObservationID(9999)); !errors.Is(err, fleet.ErrCapacity) {
				if extra != nil {
					extra.Close()
				}
				return fmt.Errorf("actual Router did not enforce capture capacity1: %w", err)
			} else {
				f.capacityRefusals++
			}
			var snapshot collector.SourceSnapshot
			if json.Unmarshal(op.Body, &snapshot) != nil || !snapshot.Valid() || snapshot.CaptureID != f.work.Accepted.CaptureID || snapshot.ExpectationDigest != [32]byte(evidence.ContextExpectationDigest(f.work.Accepted.Expectation)) || !snapshot.Request.Equal(*f.work.Accepted.Expectation.Snapshot) {
				return execution.ErrConflict
			}
			until, _ := ctx.Deadline()
			if until.After(snapshot.Request.StartBy) || until.After(f.human.ValidUntil) || !time.Now().Before(until) {
				return execution.ErrExpired
			}
			f.mu.Lock()
			f.queued[snapshot.CaptureID] = true
			first := len(f.queued) == 1
			f.mu.Unlock()
			if first {
				close(f.firstQueued)
			}
			body = struct{ Queued time.Time }{time.Now().UTC().Truncate(time.Microsecond)}
		default:
			handled = false
		}
		if handled {
			b, _ := json.Marshal(body)
			reply, err := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: op.Sequence, Method: op.Method, Body: b})
			if err != nil {
				return err
			}
			s.replies = append(s.replies, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: reply})
			return nil
		}
	}
	if op.Method != "resolve-source-snapshot" {
		return s.regionalObservationStream.Send(ctx, frame)
	}
	var original targets.SourceSnapshotTarget
	if json.Unmarshal(op.Body, &original) != nil || s.group.work.SourceTarget == nil || original != *s.group.work.SourceTarget {
		return execution.ErrDenied
	}
	now := s.group.now
	process := targets.PacketSourceObservation{PodUID: original.Request.PodUID, NodeUID: original.NodeUID, BootID: original.BootID, CollectorPodUID: original.CollectorPodUID, CollectorEpoch: original.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	observed := targets.SourceSnapshotResolution{Original: original, Process: process, State: targets.RecorderSourceState{SourceID: original.SourceID, Fence: original.Fence, IssuedAt: now, LeafUntil: now.Add(30 * time.Second), Credit: 1 << 20, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, ReportedAt: now, ReportFreshUntil: now.Add(5 * time.Second), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if !observed.Valid(time.Now()) {
		s.group.t.Error("invalid synthetic exact source observation")
		return execution.ErrInvalid
	}
	s.group.resolved = observed
	b, _ := json.Marshal(observed)
	reply, err := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: op.Sequence, Method: op.Method, Body: b})
	if err != nil {
		return err
	}
	s.replies = append(s.replies, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: reply})
	return nil
}

func newGroupRegionalFixture(t *testing.T, counts ...int) *groupRegionalFixture {
	count := 16
	if len(counts) > 0 {
		count = counts[0]
	}
	base, cap, _ := newRegionalObservationFixture(t)
	f := &groupRegionalFixture{regionalObservationFixture: base, capability: cap, retentionByPod: map[string]privacy.Resolution{}, human: base.identity, intents: map[string]auditvalue.CaptureIntent{}, queued: map[string]bool{}, records: map[string]execution.APIExecution{}, methods: map[string]int{}, ackBlocked: make(chan struct{}), releaseACK: make(chan struct{}), firstQueued: make(chan struct{})}
	human := base.identity.Principal
	owner := base.work.Accepted.Expectation.Audience[0]
	authority := authorization.AcceptedPolicyAuthority{InstallationID: base.recovery.InstallationID, PolicyUID: "group-policy", Creator: human, ScopeDigest: artifact.Digest{9}, ClusterID: base.target.Request.ClusterID, NamespaceUID: base.target.Request.Namespace.UID, WorkloadUID: base.target.Request.Workload.UID, Delegation: identity.Revision{UID: owner.BasisUID, Generation: 1, Digest: artifact.Digest{1}}, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 1, MaxBytes: 16 * artifact.RecordingNativeLimit}, IssuedAt: base.now.Add(-time.Minute), NotAfter: base.now.Add(time.Hour)}
	authority.Executor = authorization.PolicyPrincipal(authority.InstallationID, authority.PolicyUID)
	if !authority.Valid(base.now) {
		t.Fatal("invalid synthetic reviewed policy")
	}
	f.authority = authority
	base.identity = authorization.PolicyExecutorIdentity(authority, base.now, base.now.Add(5*time.Second))
	var sources []compiler.RecordingSaveScopeSource
	for i := 0; i < count; i++ {
		w := base.work
		e := w.Accepted.Expectation
		target := base.target
		target.Request.PodUID, target.Pin.UID = regionalObservationID(100+i), regionalObservationID(100+i)
		target.Request.PodName, target.Pin.Name = "api-group-"+regionalObservationID(100+i), "api-group-"+regionalObservationID(100+i)
		binding := collector.SourceBinding{RootID: regionalObservationID(41), PolicyUID: authority.PolicyUID, AcceptanceID: regionalObservationID(210), SourceID: regionalObservationID(300 + i), Fence: regionalObservationID(400 + i), ActionID: "a0123456789abcdef01234567", PodUID: target.Request.PodUID, NodeUID: regionalObservationID(501), BootID: regionalObservationID(502), CollectorPodUID: regionalObservationID(503), CollectorEpoch: regionalObservationID(504), Scope: [32]byte(authority.ScopeDigest), ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}
		audience, _ := compiler.SourceAudienceDigest(e.Audience)
		binding.AudienceDigest = [32]byte(audience)
		original := targets.SourceSnapshotTarget{Request: target.Request, Pin: target.Pin, NodeUID: binding.NodeUID, BootID: binding.BootID, CollectorPodUID: binding.CollectorPodUID, CollectorEpoch: binding.CollectorEpoch, SourceID: binding.SourceID, Fence: binding.Fence, BindingDigest: deliveryapp.SourceBindingDigest(binding)}
		request := artifact.SourceSnapshotRequest{SourceBindingDigest: original.BindingDigest, SourceID: binding.SourceID, Fence: binding.Fence, SnapshotID: regionalObservationID(600 + i), SourceStartedAt: base.now.Add(-time.Minute), SourceHardUntil: base.now.Add(time.Hour), T0: base.now, IssuedAt: base.now, StartBy: base.now.Add(5 * time.Second), ProcessingUntil: base.now.Add(30 * time.Second), Before: time.Second, MaxBytes: 65536}
		scope := &planning.SourceSnapshotContext{Group: &planning.RecordingSaveGroupBinding{ParentCaptureID: regionalObservationID(700), ChildIndex: i, ChildCount: count}, Request: request, ActionID: binding.ActionID, PolicyUID: binding.PolicyUID, TriggerKind: "recordingSave", ExecutionDigest: authority.ScopeDigest, RecipeDigest: e.RecipeDigest, SourceAudience: e.Audience, SourceAudienceDigest: audience, SourceTarget: &original, SourceDefinitionDigest: artifact.Digest(binding.ExpectationDigest)}
		retention := base.retention
		retention.Target = original.Target()
		retention.EvidenceType = "packetCapture"
		retention.AnchorAt = artifact.SourceSnapshotAnchor(request)
		retention.ExpiresAt = retention.AnchorAt.Add(60 * time.Second)
		retention.DeleteBy = retention.ExpiresAt.Add(30 * time.Second)
		retention.Proof.PodUID = target.Request.PodUID
		sources = append(sources, compiler.RecordingSaveScopeSource{PolicyUID: binding.PolicyUID, ExecutionDigest: authority.ScopeDigest, Original: original, ActionID: binding.ActionID, Kind: "packetCapture", DefinitionDigest: scope.SourceDefinitionDigest, AudienceDigest: audience, CeilingDigest: artifact.Digest(cap.Revision.Digest), RetentionDigest: artifact.Digest(retention.PolicyRevision.Digest), ApprovedBefore: time.Second, Before: time.Second, MaxBytes: 65536})
		w.Actor = authority.Executor
		w.SourceBinding = &binding
		w.SourceTarget = &original
		w.SourceAudience = e.Audience
		w.Target = target.Request
		w.Accepted.CaptureID = regionalObservationID(800 + i)
		w.Accepted.Deadline = request.ProcessingUntil
		w.Accepted.Pin = target.Pin
		e.CaptureUID, e.PodUID, e.ActionID = w.Accepted.CaptureID, target.Request.PodUID, binding.ActionID
		e.OccurrenceID = regionalObservationID(1100 + i)
		e.Registration.Location.ArtifactID = regionalObservationID(900 + i)
		e.Registration.Location.AttemptID = regionalObservationID(1000 + i)
		e.NativeType = artifact.PCAPNGArtifact
		e.Snapshot = &request
		e.Lifecycle, _ = compiler.SourceSnapshotLifecycle(scope)
		e.Registration.NativeLimit = request.MaxBytes
		e.Registration.WriteUntil = request.ProcessingUntil
		e.Registration.AnchorAt = retention.AnchorAt
		e.Registration.ExpiresAt = retention.ExpiresAt
		e.Registration.DeleteBy = retention.DeleteBy
		w.Accepted.Expectation = e
		f.works = append(f.works, w)
		f.scopes = append(f.scopes, scope)
		f.retentionByPod[e.PodUID] = retention
	}
	raw, digest, err := compiler.CompileRecordingSaveScope(compiler.RecordingSaveScopeInput{CaptureID: regionalObservationID(700), Requester: human, Authority: authority, Sources: sources, IncidentPodLimit: count, FinalizeTimeout: 30 * time.Second, CeilingDigest: artifact.Digest(cap.Revision.Digest), RetentionDigest: artifact.Digest(base.retention.PolicyRevision.Digest)}, base.now)
	if err != nil {
		t.Fatal("reviewed full parent scope", err)
	}
	for i := range f.works {
		w := &f.works[i]
		scope := f.scopes[i]
		scope.Group.SelectionDigest = digest
		scope.RecordingSaveScope = raw
		target := base.target
		target.Request = w.Target
		target.Pin = w.Accepted.Pin
		plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: w.Accepted.CaptureID, CaseID: w.Accepted.Expectation.CaseID, Executor: w.Actor, Deadline: w.Accepted.Deadline, Target: target, Capability: cap, Retention: f.retentionByPod[w.Target.PodUID], Snapshot: scope}, base.now)
		if err != nil {
			t.Fatal("valid original child plan", i, err)
		}
		e := &w.Accepted.Expectation
		e.PlanDigest = digest
		w.Accepted.ScopeDigest = digest
		binding, _ := json.Marshal(w.SourceBinding)
		e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: plan.CanonicalScope, Binding: binding}
		if e.Validate() != nil {
			t.Fatal("invalid accepted child expectation", i, e.Validate())
		}
	}
	f.parent = capturevalue.Accepted{CaptureID: regionalObservationID(700), ScopeDigest: digest, SubmissionDigest: captureapp.ContextRequestDigest(regionalObservationID(701)), State: capturevalue.IntentAudited, CreatedAt: base.now, Deadline: base.now.Add(30 * time.Second), MetadataValidUntil: base.now.Add(5 * time.Second), Group: &capturevalue.RecordingSaveGroupAccepted{CaseID: base.work.Accepted.Expectation.CaseID}}
	for i := range f.works {
		w := &f.works[i]
		w.Initiator = &f.human.Principal
		w.Accepted.SubmissionDigest = artifact.Digest{byte(i + 1)}
		f.parent.Group.Children = append(f.parent.Group.Children, w.Accepted)
		e := w.Accepted.Expectation
		encoded, _ := json.Marshal(e)
		f.intents[w.Accepted.CaptureID] = auditvalue.CaptureIntent{Group: &auditvalue.CaptureGroupBinding{ParentCaptureID: f.parent.CaptureID, SelectionDigest: digest, ChildIndex: i, ChildCount: count}, Initiator: &f.human.Principal, RootID: regionalObservationID(41), CaptureID: w.Accepted.CaptureID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, Actor: w.Actor, Target: w.SourceTarget.Target(), ScopeDigest: digest, SubmissionDigest: w.Accepted.SubmissionDigest, ExpectationDigest: sha256.Sum256(encoded), PermissionEpoch: regionalObservationID(42), PermissionSequence: 1, IdentityRevision: f.human.Policy, CreatedAt: base.now, Deadline: w.Accepted.Deadline, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy, ReservedBytes: e.Registration.ReservedBytes()}
	}
	return f
}

func TestRegionalGroupChildReachesOriginalPreparation(t *testing.T) {
	for _, count := range []int{2, 16} {
		t.Run(fmt.Sprintf("children-%d", count), func(t *testing.T) {
			f := newGroupRegionalFixture(t, count)
			f.work = f.works[0]
			f.work.Initiator = nil
			ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
			defer cancel()
			current, _, err := identities.NewBearerRequest(ctx, f, "synthetic-policy", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			router, err := contextstart.NewRouter(contextstart.RouterLimits{Standby: 2, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: f.work.Target.ClusterID, Standby: 2, Captures: 1}}})
			if err != nil {
				t.Fatal(err)
			}
			resident, end := context.WithCancel(t.Context())
			defer end()
			standby, err := router.RegisterStandby(resident, f.receiver, func(ctx context.Context) (fleet.APIContextReceiver, error) { return f.receiver, ctx.Err() })
			if err != nil {
				t.Fatal(err)
			}
			stream := &groupRegionalStream{regionalObservationStream: &regionalObservationStream{f: f.regionalObservationFixture, ctx: ctx}, group: f}
			done := make(chan error, 1)
			go func() { defer standby.Finish(); done <- standby.Serve(stream, time.Now) }()
			start := RegionalAPIContextStart{Runner: executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Eligibility: f, Capabilities: f, Retention: groupRegionalRetention{f}, Recovery: f, Now: time.Now}, Signer: f, Router: router, Now: time.Now, Report: func(s string) { t.Log(s) }}
			err = start.StartContext(ctx, current, f.work.Accepted.CaptureID)
			cancel()
			end()
			<-done
			if f.preparations != 1 {
				t.Fatalf("valid reviewed group child failed before SQL preparation: preparations=%d, error=%v", f.preparations, err)
			}
		})
	}
}

func (f *groupRegionalFixture) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	if f.complete {
		return f.human, ctx.Err()
	}
	return f.identity, ctx.Err()
}
func (f *groupRegionalFixture) ReadAPIContextWork(ctx context.Context, id string, who identity.Identity, recovery artifact.RecoveryProof) (executionapp.APIContextWork, error) {
	if !f.complete {
		return f.regionalObservationFixture.ReadAPIContextWork(ctx, id, who, recovery)
	}
	for _, w := range f.works {
		if w.Accepted.CaptureID == id && who.Principal == f.authority.Executor {
			f.work = w
			return w, ctx.Err()
		}
	}
	return executionapp.APIContextWork{}, execution.ErrDenied
}
func (f *groupRegionalFixture) PrepareAPIExecution(ctx context.Context, c executionapp.APIExecutionCheck) (execution.APIExecution, bool, error) {
	if !f.complete {
		return f.regionalObservationFixture.PrepareAPIExecution(ctx, c)
	}
	f.preparations++
	if !c.Valid(time.Now()) || ctx.Err() != nil {
		return execution.APIExecution{}, false, execution.ErrDenied
	}
	e := c.Work.Accepted.Expectation
	p := c.Process.Binding
	b := execution.Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: p.PodUID, ExecutorAccountUID: p.AccountUID, OperationID: e.CaptureUID, CaptureID: e.CaptureUID, ActionID: e.ActionID, AttemptID: e.Registration.Location.AttemptID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: e.PodUID, CollectorEpoch: p.ProcessEpoch, ScopeDigest: e.PlanDigest, AuthorityDigest: artifact.Digest{1}, BudgetDigest: artifact.Digest{2}, AuditDigest: artifact.Digest{3}, NativeBytes: e.Registration.NativeLimit, NotBefore: c.CheckedAt, NotAfter: c.ValidUntil}
	r := execution.APIExecution{WriterProtocol: artifact.ContextWriterProtocol, RootID: regionalObservationID(41), Binding: b, Process: p, ExpectationDigest: evidence.ContextExpectationDigest(e), Phase: "prepared"}
	if !r.Valid() {
		return execution.APIExecution{}, false, execution.ErrInvalid
	}
	f.records[e.CaptureUID] = r
	return r, true, nil
}
func (f *groupRegionalFixture) BindAPIStart(ctx context.Context, c executionapp.APIExecutionCheck, r execution.APIExecution, p execution.PreparedStart) (execution.APIExecution, error) {
	r.ObjectUID = p.ObjectUID
	f.records[c.Work.Accepted.CaptureID] = r
	return r, ctx.Err()
}
func (f *groupRegionalFixture) RecordAPIStart(ctx context.Context, c executionapp.APIExecutionCheck, r execution.APIExecution, d execution.Disposition) (execution.APIExecution, error) {
	r.Phase = "started"
	r.StartedAt = d.CommittedAt
	if !r.Valid() {
		return r, execution.ErrInvalid
	}
	f.records[c.Work.Accepted.CaptureID] = r
	return r, ctx.Err()
}
func (f *groupRegionalFixture) RecordAPIStoredCompletion(context.Context, execution.APIExecution, artifact.ContextWriterCompletion, execution.APIProcessObservation, artifact.RecoveryProof) (execution.APIExecution, error) {
	panic("group route test must not claim stored bytes")
}
func (f *groupRegionalFixture) AcceptedPolicyAuthority(ctx context.Context, id string) (authorization.AcceptedPolicySnapshot, error) {
	if id != f.authority.PolicyUID {
		return authorization.AcceptedPolicySnapshot{}, execution.ErrDenied
	}
	return authorization.AcceptedPolicySnapshot{Authority: f.authority, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), SourceUntil: f.now.Add(5 * time.Second)}, ctx.Err()
}
func (f *groupRegionalFixture) LookupContextAdmission(ctx context.Context, q capturevalue.ReplayQuery) (capturevalue.Accepted, bool, error) {
	if q.Identity.Principal != f.human.Principal || q.SubmissionDigest != f.parent.SubmissionDigest {
		return capturevalue.Accepted{}, false, execution.ErrDenied
	}
	return f.parent, true, ctx.Err()
}
func (f *groupRegionalFixture) AcknowledgedCaptureIntent(ctx context.Context, id string) (auditvalue.CaptureIntent, error) {
	active := f.ackActive.Add(1)
	defer f.ackActive.Add(-1)
	for old := f.ackMaximum.Load(); active > old; old = f.ackMaximum.Load() {
		if f.ackMaximum.CompareAndSwap(old, active) {
			break
		}
	}
	if id == f.works[len(f.works)-1].Accepted.CaptureID {
		close(f.ackBlocked)
		select {
		case <-ctx.Done():
			return auditvalue.CaptureIntent{}, ctx.Err()
		case <-f.releaseACK:
		}
	}
	r, ok := f.intents[id]
	if !ok || !r.Valid() {
		return auditvalue.CaptureIntent{}, execution.ErrInvalid
	}
	return r, ctx.Err()
}

type groupRegionalStartOwner struct {
	f     *groupRegionalFixture
	start RegionalAPIContextStart
}

func (s groupRegionalStartOwner) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	f := s.f
	active := f.active.Add(1)
	defer f.active.Add(-1)
	for old := f.maximum.Load(); active > old; old = f.maximum.Load() {
		if f.maximum.CompareAndSwap(old, active) {
			break
		}
	}
	if active != 1 {
		return fmt.Errorf("concurrent starts against capture capacity1")
	}
	receiver := f.receiver
	receiver.Channel.ExchangeID = id
	// Passive socket residency is independent of the short attached work.
	resident, cancel := context.WithCancel(f.t.Context())
	defer cancel()
	standby, err := s.start.Router.RegisterStandby(resident, receiver, func(ctx context.Context) (fleet.APIContextReceiver, error) { return receiver, ctx.Err() })
	if err != nil {
		return err
	}
	stream := &groupRegionalStream{regionalObservationStream: &regionalObservationStream{f: f.regionalObservationFixture, ctx: resident}, group: f}
	done := make(chan error, 1)
	go func() { defer standby.Finish(); done <- standby.Serve(stream, time.Now) }()
	err = s.start.StartContext(ctx, current, id)
	cancel()
	<-done // join exact standby/stream before releasing this serial start
	return err
}

func TestRegionalGroupRouterQueuesEarlierChildWhileLastAuditBlocked(t *testing.T) {
	f := newGroupRegionalFixture(t)
	f.complete = true
	caller, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	current, _, err := identities.NewBearerRequestWithin(caller, f, "synthetic-human", time.Now, identity.RecordingSaveRequestWindow)
	if err != nil {
		t.Fatal(err)
	}
	router, err := contextstart.NewRouter(contextstart.RouterLimits{Standby: 2, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: f.work.Target.ClusterID, Standby: 2, Captures: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	f.router = router
	regional := RegionalAPIContextStart{Runner: executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Eligibility: f, Capabilities: f, Retention: groupRegionalRetention{f}, Recovery: f, Now: time.Now}, Signer: f, Router: router, Now: time.Now, Report: func(s string) { t.Log(s) }}
	_, services := publicContextOperationFixture(t)
	investigation := services.Investigation
	investigation.RootID = regionalObservationID(41)
	investigation.InstallationID = f.recovery.InstallationID
	investigation.Replay = f
	investigation.Recovery = f
	investigation.PolicyAccepted = f
	investigation.RecordingSaveEnabled = true
	investigation.Now = time.Now
	investigation.NewID = func() string { return regionalObservationID(1000) }
	submission := captureapp.ContextSubmission{ContextInvestigation: investigation, Intents: f, Start: groupRegionalStartOwner{f, regional}}
	done := make(chan error, 1)
	go func() {
		_, err := submission.Continue(caller, current, regionalObservationID(701), "original-group")
		done <- err
	}()
	select {
	case <-caller.Done():
		t.Fatal("ACK worker not reached", caller.Err())
	case <-f.ackBlocked:
	}
	select {
	case <-caller.Done():
		t.Fatal("last audit stalled earlier exact child", caller.Err())
	case <-f.firstQueued:
	}
	f.mu.Lock()
	before := len(f.queued)
	f.mu.Unlock()
	if before < 1 || before == 16 {
		t.Fatal("invalid pipeline observation", before)
	}
	close(f.releaseACK)
	if err := <-done; err != nil {
		t.Fatal("actual composed group dispatch", err)
	}
	if len(f.queued) != 16 || len(f.records) != 16 || f.preparations != 16 || f.maximum.Load() != 1 || f.ackActive.Load() != 0 || f.ackMaximum.Load() > 16 || f.capacityRefusals != 16 {
		t.Fatal("group lost work or ownership", len(f.queued), len(f.records), f.preparations, f.maximum.Load(), f.ackActive.Load())
	}
	for _, method := range []string{"resolve-source-snapshot", "read-process", "prepare-output", "prepare-start", "ready-start", "consume-start", "start-source-snapshot", "finish"} {
		if f.methods[method] != 16 {
			t.Fatal("control pipeline missing", method, f.methods)
		}
	}
	t.Logf("actual Router Standby2/Captures1: queued16, maxactive=%d, ACKworkers<=%d, earlierqueued=%d whilelastACKblocked; synthetic authority/node/SQL only", f.maximum.Load(), f.ackMaximum.Load(), before)
}
