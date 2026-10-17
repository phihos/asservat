package execution

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type contextExecutionFixture struct {
	now                                                              time.Time
	receiver                                                         fleet.Receiver
	action                                                           fleet.AuthenticatedAction
	resolved                                                         value.ContextStart
	mode                                                             string
	spent                                                            atomic.Bool
	verifies, resolves, prepares, consumes, captures, stores, closes atomic.Int64
}

func (f *contextExecutionFixture) VerifyRunAction(context.Context, []byte, fleet.Receiver) (fleet.AuthenticatedAction, error) {
	n := f.verifies.Add(1)
	if f.mode == "signature" {
		return fleet.AuthenticatedAction{}, value.ErrDenied
	}
	a := f.action
	if f.mode == "key-revoked" && n > 1 {
		return fleet.AuthenticatedAction{}, value.ErrDenied
	}
	return a, nil
}
func (f *contextExecutionFixture) ResolveContextWork(context.Context, fleet.AuthenticatedAction, fleet.Receiver) (value.ContextStart, error) {
	n := f.resolves.Add(1)
	if f.mode == "authority" || f.mode == "revoked-after-keys" && n > 1 {
		return value.ContextStart{}, value.ErrDenied
	}
	out := f.resolved
	if n > 1 {
		switch f.mode {
		case "replacement-reservation":
			out.Start.ObjectUID = contextID(20)
		case "changed-audience":
			out.Expectation.Audience[0].SubjectID = "different-team"
		}
	}
	return out, nil
}
func (f *contextExecutionFixture) LookupStart(context.Context, value.Request) (value.Disposition, error) {
	if f.mode == "lookup" {
		return value.Disposition{}, value.ErrUnavailable
	}
	phase := value.Ready
	if f.spent.Load() {
		phase = value.StartCommitted
	}
	return value.Disposition{ObjectUID: f.resolved.Start.ObjectUID, ResourceVersion: "1", Phase: phase, ValidUntil: f.resolved.Start.ValidUntil}, nil
}
func (f *contextExecutionFixture) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	f.consumes.Add(1)
	won := f.spent.CompareAndSwap(false, true)
	if f.mode == "lost-start-reply" {
		return value.Disposition{}, value.ErrUnavailable
	}
	d := value.Disposition{ObjectUID: f.resolved.Start.ObjectUID, ResourceVersion: "2", Phase: value.StartCommitted, CommittedAt: f.now, MayStart: won, ValidUntil: f.resolved.Start.ValidUntil}
	if f.mode == "expiry-after-start" {
		f.now = f.now.Add(6 * time.Second)
	}
	return d, nil
}
func (f *contextExecutionFixture) PrepareContext(_ context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	f.prepares.Add(1)
	if f.mode == "keys" {
		return nil, value.ErrUnavailable
	}
	return &preparedExecutionFixture{f: f, expectation: e}, nil
}

type preparedExecutionFixture struct {
	f           *contextExecutionFixture
	expectation artifact.ContextExpectation
	copies      artifact.Copies
	once        sync.Once
}

func (p *preparedExecutionFixture) Close() { p.once.Do(func() { p.f.closes.Add(1) }) }
func (p *preparedExecutionFixture) CompleteStored() (artifact.ContextWriterCompletion, error) {
	p.Close()
	if p.copies == (artifact.Copies{}) {
		return artifact.ContextWriterCompletion{}, value.ErrUnavailable
	}
	return artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(p.expectation.Registration), ExpectationDigest: evidence.ContextExpectationDigest(p.expectation), Copies: p.copies, StoredAt: p.f.now, ClosedAt: p.f.now}, nil
}
func (p *preparedExecutionFixture) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	p.f.stores.Add(1)
	if p.f.mode == "write" {
		return artifact.Copies{}, value.ErrUnavailable
	}
	var copies artifact.Copies
	for i := range copies {
		copies[i] = artifact.CopyReceipt{VersionID: "v1", ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{byte(i + 1)}}
	}
	p.copies = copies
	return copies, nil
}
func (f *contextExecutionFixture) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	f.captures.Add(1)
	if f.mode == "capture" {
		return nil, value.ErrUnavailable
	}
	if f.mode == "oversize" {
		return make([]byte, artifact.MaxContextBytes+1), nil
	}
	return []byte("synthetic control-flow fixture; native format tested by real writer"), nil
}
func contextID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func executionFixture() (*contextExecutionFixture, ContextExecutor) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := fleet.Receiver{PeerID: contextID(1), ClusterID: contextID(2), IssuerEpoch: contextID(3), NodeUID: contextID(4), NodeBootID: contextID(5), CollectorEpoch: contextID(6), Region: "eu-test", Capabilities: []string{"pod-status/v1"}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	w := fleet.RunAction{WorkID: contextID(7), OperationID: contextID(8), ClusterID: r.ClusterID, IssuerEpoch: r.IssuerEpoch, DeliveryFence: 1, IssuedAt: now, NotAfter: now.Add(30 * time.Second), ScopeDigest: artifact.Digest{1}, RequiredCapabilities: []string{"pod-status/v1"}, PodUID: contextID(9), NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, CaptureID: contextID(10), ActionID: "pod-status", AttemptID: contextID(11)}
	w.Scope = fleet.Reference{ID: contextID(12), Region: r.Region, Digest: w.ScopeDigest, ExpiresAt: w.NotAfter}
	w.Authority = fleet.Reference{ID: contextID(13), Region: r.Region, Digest: artifact.Digest{2}, ExpiresAt: w.NotAfter}
	w.Budget = fleet.Reference{ID: contextID(14), Region: r.Region, Digest: artifact.Digest{3}, ExpiresAt: w.NotAfter}
	w.Audit = fleet.Reference{ID: contextID(15), Region: r.Region, Digest: artifact.Digest{4}, ExpiresAt: w.NotAfter}
	a := fleet.AuthenticatedAction{Work: w, KeyID: "work-key", TrustRevision: identity.Revision{UID: "trust", Generation: 1, Digest: artifact.Digest{5}}, VerifiedAt: now, ValidUntil: r.ValidUntil}
	b := value.Binding{OperationID: w.OperationID, CaptureID: w.CaptureID, ActionID: w.ActionID, AttemptID: w.AttemptID, ClusterID: r.ClusterID, IssuerEpoch: r.IssuerEpoch, PodUID: w.PodUID, NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, CollectorEpoch: r.CollectorEpoch, ScopeDigest: w.ScopeDigest, AuthorityDigest: w.Authority.Digest, BudgetDigest: w.Budget.Digest, AuditDigest: w.Audit.Digest, NativeBytes: 4096, NotBefore: now, NotAfter: w.NotAfter}
	e := artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: r.ClusterID, ArtifactID: contextID(16), AttemptID: w.AttemptID}, StoreID: contextID(17), AllocationID: contextID(18), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(60 * time.Second), DeleteBy: now.Add(90 * time.Second)}, CaseID: contextID(21), OccurrenceID: contextID(22), NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, PodUID: w.PodUID, Namespace: "payments", NamespaceUID: contextID(23), WorkloadUID: contextID(24), CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{6}, RecipeDigest: artifact.Digest{7}, PlanDigest: w.ScopeDigest, CaptureUID: w.CaptureID, ActionID: w.ActionID, DataClass: "metadata", PurposeRef: "diagnostics", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: contextID(25), AssignmentID: contextID(26), BasisDigest: artifact.Digest{8}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 120, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: contextID(27), Generation: 1, Digest: artifact.Digest{9}}}, TriggeredAt: now}
	resolved := value.ContextStart{Start: value.Request{Binding: b, ObjectUID: contextID(28), CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, Expectation: e, Pin: artifact.PinnedPod{Namespace: e.Namespace, NamespaceUID: e.NamespaceUID, Name: "api", UID: e.PodUID, NodeName: "synthetic-node"}}
	f := &contextExecutionFixture{now: now, receiver: r, action: a, resolved: resolved}
	return f, ContextExecutor{Work: f, Resolve: f, Starts: f, Output: f, Collector: f, Now: func() time.Time { return f.now }}
}
func TestContextExecutionHasOneEffectUnderConcurrentDelivery(t *testing.T) {
	f, s := executionFixture()
	var wg sync.WaitGroup
	var stored, already atomic.Int64
	for range 8 {
		wg.Go(func() {
			out, err := s.Execute(context.Background(), []byte("synthetic-signed-input"), f.receiver)
			if err != nil {
				t.Error(err)
				return
			}
			switch out.State {
			case "StoredPendingVerification":
				stored.Add(1)
			case "AlreadyStarted":
				already.Add(1)
			default:
				t.Error("unexpected disposition")
			}
		})
	}
	wg.Wait()
	if stored.Load() != 1 || already.Load() != 7 || f.captures.Load() != 1 || f.stores.Load() != 1 || f.prepares.Load() != f.closes.Load() {
		t.Fatal("duplicate effect or unclosed keys", stored.Load(), already.Load(), f.captures.Load())
	}
	before := f.prepares.Load()
	out, err := s.Execute(context.Background(), []byte("retry"), f.receiver)
	if err != nil || out.State != "AlreadyStarted" || f.prepares.Load() != before {
		t.Fatal("retry minted new keys", err)
	}
}
func TestContextExecutionFailuresCannotAcquireBeforeAuthorityAndSpend(t *testing.T) {
	for _, mode := range []string{"signature", "authority", "lookup", "keys", "key-revoked", "revoked-after-keys", "replacement-reservation", "changed-audience", "expiry-after-start"} {
		t.Run(mode, func(t *testing.T) {
			f, s := executionFixture()
			f.mode = mode
			out, err := s.Execute(context.Background(), []byte("synthetic"), f.receiver)
			if err == nil || f.captures.Load() != 0 || f.stores.Load() != 0 || out.Copies != (artifact.Copies{}) {
				t.Fatal("failed boundary acquired evidence", out.State, err)
			}
		})
	}
}
func TestContextExecutionLostStartAndPostStartFailuresNeverRetryEffect(t *testing.T) {
	for _, mode := range []string{"lost-start-reply", "capture", "oversize", "write"} {
		t.Run(mode, func(t *testing.T) {
			f, s := executionFixture()
			f.mode = mode
			out, err := s.Execute(context.Background(), []byte("synthetic"), f.receiver)
			if err == nil || out.State != "Indeterminate" || !f.spent.Load() {
				t.Fatal("uncertain effect became retryable", err)
			}
			before := f.captures.Load()
			out, err = s.Execute(context.Background(), []byte("same effect"), f.receiver)
			if err != nil || out.State != "AlreadyStarted" || f.captures.Load() != before {
				t.Fatal("failed effect repeated", err)
			}
		})
	}
}
func TestContextExecutionRejectsReplacedCollectorOrMismatchedReference(t *testing.T) {
	for _, mode := range []string{"collector", "epoch", "budget", "scope", "audit", "raw", "capability"} {
		t.Run(mode, func(t *testing.T) {
			f, s := executionFixture()
			switch mode {
			case "collector":
				f.receiver.CollectorEpoch = contextID(30)
			case "epoch":
				f.receiver.IssuerEpoch = contextID(30)
			case "budget":
				f.resolved.Start.Binding.BudgetDigest[0]++
			case "scope":
				f.resolved.Expectation.PlanDigest[0]++
			case "audit":
				f.resolved.Start.Binding.AuditDigest[0]++
			case "raw":
				f.resolved.Expectation.DataClass = "raw"
			case "capability":
				f.action.Work.RequiredCapabilities = nil
			}
			if _, err := s.Execute(context.Background(), []byte("synthetic"), f.receiver); err == nil || f.prepares.Load() != 0 || f.consumes.Load() != 0 || f.captures.Load() != 0 {
				t.Fatal("mismatched scope reached effect", err)
			}
		})
	}
}
