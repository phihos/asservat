package execution

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
)

// fixtureContext is the synthetic accepted start the API runner tests derive
// their binding, expectation and pin from.
type fixtureContext struct {
	Start struct {
		Binding    value.Binding
		ValidUntil time.Time
	}
	Expectation artifact.ContextExpectation
	Pin         artifact.PinnedPod
}

type contextExecutionFixture struct {
	now                                          time.Time
	receiver                                     fleet.Receiver
	resolved                                     fixtureContext
	mode                                         string
	spent                                        atomic.Bool
	prepares, consumes, captures, stores, closes atomic.Int64
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
func executionFixture() *contextExecutionFixture {
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := fleet.Receiver{PeerID: contextID(1), ClusterID: contextID(2), IssuerEpoch: contextID(3), NodeUID: contextID(4), NodeBootID: contextID(5), CollectorEpoch: contextID(6), Region: "eu-test", Capabilities: []string{"pod-status/v1"}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	notAfter := now.Add(30 * time.Second)
	b := value.Binding{OperationID: contextID(8), CaptureID: contextID(10), ActionID: "pod-status", AttemptID: contextID(11), ClusterID: r.ClusterID, IssuerEpoch: r.IssuerEpoch, PodUID: contextID(9), NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, CollectorEpoch: r.CollectorEpoch, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: 4096, NotBefore: now, NotAfter: notAfter}
	e := artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: r.ClusterID, ArtifactID: contextID(16), AttemptID: b.AttemptID}, StoreID: contextID(17), AllocationID: contextID(18), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(60 * time.Second), DeleteBy: now.Add(90 * time.Second)}, CaseID: contextID(21), OccurrenceID: contextID(22), NodeUID: r.NodeUID, NodeBootID: r.NodeBootID, PodUID: b.PodUID, Namespace: "payments", NamespaceUID: contextID(23), WorkloadUID: contextID(24), CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{6}, RecipeDigest: artifact.Digest{7}, PlanDigest: b.ScopeDigest, CaptureUID: b.CaptureID, ActionID: b.ActionID, DataClass: "metadata", PurposeRef: "diagnostics", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: contextID(25), AssignmentID: contextID(26), BasisDigest: artifact.Digest{8}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 120, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: contextID(27), Generation: 1, Digest: artifact.Digest{9}}}, TriggeredAt: now}
	f := &contextExecutionFixture{now: now, receiver: r}
	f.resolved.Start.Binding, f.resolved.Start.ValidUntil = b, now.Add(5*time.Second)
	f.resolved.Expectation = e
	f.resolved.Pin = artifact.PinnedPod{Namespace: e.Namespace, NamespaceUID: e.NamespaceUID, Name: "api", UID: e.PodUID, NodeName: "synthetic-node"}
	return f
}
