package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Only the bounded coalescing state is under test here. This synthetic positive
// input stands for a separately completed full proof; native tests exercise the
// concrete token/guard/workload producer and real input changes.
func connectorCachedProof(t *testing.T, now time.Time) connectorAPIProof {
	t.Helper()
	process := fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: ownerID(1), ClusterID: ownerID(2), IssuerEpoch: ownerID(3), PeerID: ownerID(4), Role: fleet.ConnectorPeer}, PodUID: ownerID(5), ProcessEpoch: ownerID(6)}
	profile := fleet.ConnectorCredentialProfile{RootID: ownerID(7), Binding: process.Binding, Revision: identity.Revision{UID: ownerID(8), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.example", Deployment: fleet.ConnectorDeployment{Namespace: "connector", NamespaceUID: ownerID(9), ServiceAccount: "connector", AccountUID: ownerID(10), Deployment: "connector", DeploymentUID: ownerID(11), ServingSlots: 1, RetainedProcesses: 2}, ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}}
	observation := fleet.ConnectorCredentialObservation{Profile: profile, Backing: fleet.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{3}, SourceDigest: artifact.Digest{4}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	proof := fleet.ConnectorProcessProof{Process: process, Configuration: observation, Pod: "connector-pod", ReplicaSet: "connector-rs", ReplicaSetUID: ownerID(12), ClientKeyDigest: artifact.Digest{5}, ServerKeyDigest: artifact.Digest{6}, TokenDigest: artifact.Digest{7}, WorkloadDigest: artifact.Digest{8}, ProtectionDigest: artifact.Digest{9}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	p := connectorAPIProof{proof: proof, owned: mtls.ConnectorProcessObservation{Request: fleet.ConnectorProcessRequest{Process: process}, ValidUntil: now.Add(5 * time.Second)}, observedAt: now, validUntil: now.Add(5 * time.Second)}
	if !p.valid(now) {
		t.Fatal("synthetic completed observation invalid")
	}
	return p
}
func TestConnectorAPIProofCoalescesOriginalInterval(t *testing.T) {
	now := time.Now().UTC()
	proof := connectorCachedProof(t, now)
	var state connectorAPIProofState
	var producers, checks atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	produce := func(context.Context) (connectorAPIProof, error) {
		producers.Add(1)
		close(entered)
		<-release
		return proof, nil
	}
	check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { checks.Add(1); return p, nil }
	result := make(chan error, 17)
	go func() { _, e := state.read(context.Background(), time.Now, produce, check); result <- e }()
	<-entered
	waiters := make([]*connectorProofWaitContext, 16)
	for i := range waiters {
		waiters[i] = &connectorProofWaitContext{Context: context.Background(), waiting: make(chan struct{})}
		go func(c *connectorProofWaitContext) {
			p, e := state.read(c, time.Now, produce, check)
			if e == nil && (p.observedAt != proof.observedAt || p.validUntil != proof.validUntil) {
				e = cfg.ErrChanged
			}
			result <- e
		}(waiters[i])
	}
	for _, c := range waiters {
		<-c.waiting
	}
	close(release)
	for range 17 {
		if e := <-result; e != nil {
			t.Fatal(e)
		}
	}
	if producers.Load() != 1 || checks.Load() != 0 {
		t.Fatal("overlapping reads repeated proof work", producers.Load(), checks.Load())
	}
	short, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	p, e := state.read(short, time.Now, produce, check)
	end, _ := short.Deadline()
	if e != nil || p.observedAt != proof.observedAt || p.validUntil.After(end) || !p.validUntil.Before(proof.validUntil) {
		t.Fatal("short caller or original dates changed", e)
	}
	p, e = state.read(context.Background(), time.Now, produce, check)
	if e != nil || p.observedAt != proof.observedAt || p.validUntil != proof.validUntil || checks.Load() == 0 {
		t.Fatal("current rechecks renewed or erased original proof", e)
	}
}
func TestConnectorAPIProofCancelledWaiterDoesNotDetachProducer(t *testing.T) {
	proof := connectorCachedProof(t, time.Now().UTC())
	var state connectorAPIProofState
	entered, release := make(chan struct{}), make(chan struct{})
	leader := make(chan error, 1)
	produce := func(context.Context) (connectorAPIProof, error) { close(entered); <-release; return proof, nil }
	check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { return p, nil }
	go func() { _, e := state.read(context.Background(), time.Now, produce, check); leader <- e }()
	<-entered
	waiter, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := &connectorProofWaitContext{Context: waiter, waiting: make(chan struct{})}
	waitResult := make(chan error, 1)
	go func() { _, e := state.read(waiting, time.Now, produce, check); waitResult <- e }()
	<-waiting.waiting
	cancel()
	if e := <-waitResult; e == nil {
		t.Fatal("cancelled waiter reused in-flight result")
	}
	select {
	case <-leader:
		t.Fatal("waiter detached producer")
	default:
	}
	close(release)
	if e := <-leader; e != nil {
		t.Fatal(e)
	}
}
func TestConnectorAPIProofCannotPublishAfterCancellationExpiryOrKnownChange(t *testing.T) {
	for _, mode := range []string{"cancelled-owner", "expired-proof", "known-change"} {
		t.Run(mode, func(t *testing.T) {
			n := time.Now().UTC()
			proof := connectorCachedProof(t, n)
			var state connectorAPIProofState
			var clock atomic.Int64
			clock.Store(n.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			produce := func(context.Context) (connectorAPIProof, error) { close(entered); <-release; return proof, nil }
			check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) { return p, nil }
			go func() { _, e := state.read(ctx, now, produce, check); result <- e }()
			<-entered
			switch mode {
			case "cancelled-owner":
				cancel()
			case "expired-proof":
				clock.Store(n.Add(5 * time.Second).UnixNano())
			case "known-change":
				state.invalidate()
			}
			close(release)
			if e := <-result; e == nil {
				t.Fatal("late original producer published positive result")
			}
			state.mu.Lock()
			cached := state.cached
			state.mu.Unlock()
			if cached != nil {
				t.Fatal("unusable producer was retained")
			}
		})
	}
}
func TestConnectorAPIProofCurrentFailureHasNoStaleFallback(t *testing.T) {
	proof := connectorCachedProof(t, time.Now().UTC())
	var state connectorAPIProofState
	var current atomic.Bool
	current.Store(true)
	var calls atomic.Int64
	produce := func(context.Context) (connectorAPIProof, error) {
		calls.Add(1)
		if !current.Load() {
			return connectorAPIProof{}, cfg.ErrChanged
		}
		return proof, nil
	}
	check := func(context.Context, connectorAPIProof) (connectorAPIProof, error) {
		return connectorAPIProof{}, cfg.ErrChanged
	}
	if _, e := state.read(context.Background(), time.Now, produce, check); e != nil {
		t.Fatal(e)
	}
	current.Store(false)
	if _, e := state.read(context.Background(), time.Now, produce, check); e == nil {
		t.Fatal("known current mismatch reused old positive")
	}
	if _, e := state.read(context.Background(), time.Now, produce, check); e == nil || calls.Load() != 2 {
		t.Fatal("failed fresh proof fell back to cached authority", e, calls.Load())
	}
}
func TestConnectorAPIProofRecheckCannotReanchorOrRenew(t *testing.T) {
	for _, mode := range []string{"start", "expiry", "identity"} {
		t.Run(mode, func(t *testing.T) {
			proof := connectorCachedProof(t, time.Now().UTC())
			var state connectorAPIProofState
			produce := func(context.Context) (connectorAPIProof, error) { return proof, nil }
			check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) {
				switch mode {
				case "start":
					p.observedAt = p.observedAt.Add(time.Millisecond)
				case "expiry":
					p.validUntil = p.validUntil.Add(time.Millisecond)
				case "identity":
					p.proof.Process.ProcessEpoch = ownerID(99)
				}
				return p, nil
			}
			if _, e := state.read(context.Background(), time.Now, produce, check); e != nil {
				t.Fatal(e)
			}
			if _, e := state.read(context.Background(), time.Now, produce, check); e == nil {
				t.Fatal("cheap read replaced immutable proof boundary")
			}
		})
	}
}

// Done is first consulted after the in-flight proof has been selected. Tests
// use this handshake to prove a waiter actually joined, without timed sleeps.
type connectorProofWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *connectorProofWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
func TestConnectorAPIProofBlockedRecheckCannotPublishKnownChange(t *testing.T) {
	proof := connectorCachedProof(t, time.Now().UTC())
	var state connectorAPIProofState
	produce := func(context.Context) (connectorAPIProof, error) { return proof, nil }
	entered, release := make(chan struct{}), make(chan struct{})
	check := func(_ context.Context, p connectorAPIProof) (connectorAPIProof, error) {
		close(entered)
		<-release
		return p, nil
	}
	if _, e := state.read(context.Background(), time.Now, produce, check); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := state.read(context.Background(), time.Now, produce, check); result <- e }()
	<-entered
	state.invalidate()
	close(release)
	if e := <-result; e == nil {
		t.Fatal("old current recheck overwrote known-change generation")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.cached != nil {
		t.Fatal("stale recheck remained cached")
	}
}
