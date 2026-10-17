package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type connectorObservationAttesterFunc func(context.Context, value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error)

func (f connectorObservationAttesterFunc) ReadConnectorObservationProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
	return f(ctx, r)
}

type connectorObservationWorkloadFunc func(context.Context, value.ConnectorProcessIdentity, string) (value.ConnectorObservationWorkload, error)

func (f connectorObservationWorkloadFunc) ObserveConnectorWorkload(ctx context.Context, p value.ConnectorProcessIdentity, pod string) (value.ConnectorObservationWorkload, error) {
	return f(ctx, p, pod)
}

// Only the new conversation must avoid recursive local SQL/source traversal.
// Native attestation still supplies two fresh full source reads; hub SQL49 is a
// separate required pre/post gate, not replaced by these synthetic test proofs.
type connectorObservationReadTrap struct{ calls atomic.Int32 }

func (t *connectorObservationReadTrap) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	t.calls.Add(1)
	return value.ConnectorIdentitySource{}, value.ErrUnavailable
}
func (t *connectorObservationReadTrap) ConnectorLeafRegistration(context.Context, value.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	t.calls.Add(1)
	return app.ConnectorLeafRegistration{}, value.ErrUnavailable
}

func connectorObservationSyntheticAttestation(f *connectorPairFixture, p value.ConnectorObservationPin, ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
	first, err := f.ReadConnectorIdentitySource(ctx)
	if err != nil {
		return value.ConnectorObservationAttestation{}, err
	}
	a, err := EnrollmentKey(r.ClientCSRDER)
	if err != nil {
		return value.ConnectorObservationAttestation{}, err
	}
	b, err := EnrollmentKey(r.ServerCSRDER)
	if err != nil {
		return value.ConnectorObservationAttestation{}, err
	}
	last, err := f.ReadConnectorIdentitySource(ctx)
	if err != nil || !last.Observation.SameSource(first.Observation) || last.Roles != first.Roles || ctx.Err() != nil {
		return value.ConnectorObservationAttestation{}, value.ErrUnavailable
	}
	return value.ConnectorObservationAttestation{Source: first, Proof: value.ConnectorProcessProof{Process: r.Process, Configuration: first.Observation, Pod: "connector-1", ReplicaSet: "connector-rs", ReplicaSetUID: ownerTestID, ClientKeyDigest: a, ServerKeyDigest: b, TokenDigest: artifact.Digest{33}, WorkloadDigest: artifact.Digest{34}, ProtectionDigest: p.ProtectionDigest, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}}, nil
}

func TestConnectorObservationProducerUsesPrivateKeysAndFreshNativeProof(t *testing.T) {
	f, c, p, _, local, ctx, state := connectorObservationTestTLS(t)
	trap := &connectorObservationReadTrap{}
	c.source, c.registry = trap, trap
	proofCalls, workCalls := 0, 0
	attester := connectorObservationAttesterFunc(func(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
		proofCalls++
		return connectorObservationSyntheticAttestation(f, p, ctx, r)
	})
	work := connectorObservationWorkloadFunc(func(ctx context.Context, process value.ConnectorProcessIdentity, pod string) (value.ConnectorObservationWorkload, error) {
		workCalls++
		return value.ConnectorObservationWorkload{Process: process, Pod: pod, ReplicaSetUID: ownerTestID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}, nil
	})
	producer, err := NewConnectorObservationProducer(p, c, attester, work, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	for ordinal := 1; ordinal <= 4; ordinal++ {
		reply, err := producer.observe(ctx, state, local.Registration.Certificate, r, ordinal)
		if err != nil || reply.Ordinal != ordinal || proofCalls != ordinal || workCalls != ordinal || trap.calls.Load() != 0 {
			t.Fatal("fresh native proof or private-only snapshot lost", ordinal, proofCalls, workCalls, trap.calls.Load(), err)
		}
	}
	// This optimization is not a substitute for ordinary consumers' independent
	// current source/SQL registration. That method must still hit the trap.
	if _, err = c.ObserveConnectorProcess(ctx); err == nil || trap.calls.Load() != 1 {
		t.Fatal("ordinary observation weakened", err, trap.calls.Load())
	}
}

func TestConnectorObservationProducerRejectsChangedLocalAuthority(t *testing.T) {
	for _, mode := range []string{"roles", "suspended", "backing", "wrong-client-key", "wrong-server-key", "guard", "template", "replacement", "renewal", "key-replaced", "cancelled", "closed", "expired", "issuer-revoked", "proof-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, c, p, _, local, outer, state := connectorObservationTestTLS(t)
			ctx, cancel := context.WithCancel(outer)
			defer cancel()
			attester := connectorObservationAttesterFunc(func(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
				x, err := connectorObservationSyntheticAttestation(f, p, ctx, r)
				switch mode {
				case "roles":
					x.Source.Roles.Source = "other_source"
				case "suspended":
					x.Source.Observation.Profile.Suspended = true
					x.Proof.Configuration = x.Source.Observation
				case "backing":
					x.Source.Observation.Backing.Revision++
				case "wrong-client-key":
					x.Proof.ClientKeyDigest = artifact.Digest{99}
				case "wrong-server-key":
					x.Proof.ServerKeyDigest = artifact.Digest{99}
				case "guard":
					x.Proof.ProtectionDigest = artifact.Digest{99}
				case "issuer-revoked":
					x.Source.Observation.Profile.ClientIssuerRoots = [][]byte{f.serverCA.cert.Raw}
					x.Proof.Configuration = x.Source.Observation
				case "proof-unavailable":
					return value.ConnectorObservationAttestation{}, value.ErrUnavailable
				}
				return x, err
			})
			work := connectorObservationWorkloadFunc(func(ctx context.Context, process value.ConnectorProcessIdentity, pod string) (value.ConnectorObservationWorkload, error) {
				x := value.ConnectorObservationWorkload{Process: process, Pod: pod, ReplicaSetUID: ownerTestID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: f.clock(), FreshUntil: f.clock().Add(5 * time.Second)}
				switch mode {
				case "template":
					x.TemplateDigest = artifact.Digest{99}
				case "replacement":
					c.mu.Lock()
					copy := *c.active
					c.active = &copy
					c.mu.Unlock()
				case "renewal":
					c.mu.Lock()
					c.active.installed[0].Digest = artifact.Digest{99}
					c.mu.Unlock()
				case "key-replaced":
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return x, err
					}
					c.mu.Lock()
					c.active.keys[0] = key
					c.mu.Unlock()
				case "cancelled":
					cancel()
				case "closed":
					c.Close()
				case "expired":
					f.advance.Store(int64(5 * time.Second))
				}
				return x, nil
			})
			producer, err := NewConnectorObservationProducer(p, c, attester, work, f.clock)
			if err != nil {
				t.Fatal(err)
			}
			r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
			if reply, err := producer.observe(ctx, state, local.Registration.Certificate, r, 1); err == nil || reply.Format != "" {
				t.Fatal("changed local authority yielded source proof", mode, err)
			}
		})
	}
}

func TestConnectorObservationProducerKeepsCallerDeadlineAndJoinsRootCancellation(t *testing.T) {
	f, c, p, _, local, outer, state := connectorObservationTestTLS(t)
	deadline := time.Now().Add(500 * time.Millisecond)
	ctx, cancel := context.WithDeadline(outer, deadline)
	defer cancel()
	entered, finished := make(chan struct{}), make(chan error, 1)
	attester := connectorObservationAttesterFunc(func(call context.Context, r value.ConnectorProcessRequest) (value.ConnectorObservationAttestation, error) {
		d, ok := call.Deadline()
		if !ok || d.After(deadline) {
			t.Error("caller deadline renewed")
		}
		close(entered)
		<-call.Done()
		return value.ConnectorObservationAttestation{}, call.Err()
	})
	work := connectorObservationWorkloadFunc(func(context.Context, value.ConnectorProcessIdentity, string) (value.ConnectorObservationWorkload, error) {
		t.Error("cancelled proof reached template lookup")
		return value.ConnectorObservationWorkload{}, value.ErrUnavailable
	})
	producer, err := NewConnectorObservationProducer(p, c, attester, work, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	go func() { _, err := producer.observe(ctx, state, local.Registration.Certificate, r, 1); finished <- err }()
	<-entered
	c.Close()
	if err := <-finished; err == nil {
		t.Fatal("root cancellation returned proof")
	}
}

func TestConnectorObservationPrivateSnapshotRejectsActualRenewalAndReplacement(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	old, err := c.observationKeys(context.Background(), c.active.installed[0])
	if err != nil {
		t.Fatal(err)
	}
	f.advance.Store(int64(29 * time.Minute))
	if err = c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.active != old.process || !old.leaf.Valid(f.clock()) {
		t.Fatal("fixture did not retain live same-process old leaf")
	}
	if c.observationKeysCurrent(context.Background(), old) == nil {
		t.Fatal("same-process renewed leaf accepted as original handshake leaf")
	}
	renewed, err := c.observationKeys(context.Background(), c.active.installed[0])
	if err != nil {
		t.Fatal(err)
	}
	f.advance.Store(int64(32 * time.Minute))
	if err = c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.active == renewed.process || !renewed.leaf.Valid(f.clock()) {
		t.Fatal("fixture did not replace process while original renewed leaf remained live")
	}
	if c.observationKeysCurrent(context.Background(), renewed) == nil {
		t.Fatal("replacement process inherited original conversation")
	}
}

func TestConnectorObservationPrivateSnapshotHasNoActivationAuthority(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys, err := c.observationKeys(context.Background(), c.active.installed[0])
	if err != nil {
		t.Fatal(err)
	}
	source, _ := f.ReadConnectorIdentitySource(context.Background())
	if err = c.verifyObservationKeys(keys, source.Observation); err != nil {
		t.Fatal(err)
	}
	changed := source.Observation
	changed.Profile = source.Observation.Profile.Clone()
	changed.Profile.ClientIssuerRoots = [][]byte{f.serverCA.cert.Raw}
	if c.verifyObservationKeys(keys, changed) == nil {
		t.Fatal("current issuer revocation ignored")
	}
	f.revoked.Store(true)
	if err = c.observationKeysCurrent(context.Background(), keys); err != nil {
		t.Fatal("local snapshot unexpectedly claims independent SQL revocation", err)
	}
	if _, err = f.ConnectorLeafRegistration(context.Background(), keys.leaf); err == nil {
		t.Fatal("snapshot substituted for required independent hub SQL activation")
	}
}
