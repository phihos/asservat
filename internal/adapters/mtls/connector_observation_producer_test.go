package mtls

import (
	"context"
	"sync/atomic"
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

// lateTimerContext models a context whose deadline has passed while the timer
// that cancels it has not yet run, as a loaded machine can show after the key
// mutex wait (CI run 39030184148).
type lateTimerContext struct {
	context.Context
	deadline time.Time
}

func (c lateTimerContext) Deadline() (time.Time, bool) { return c.deadline, true }
