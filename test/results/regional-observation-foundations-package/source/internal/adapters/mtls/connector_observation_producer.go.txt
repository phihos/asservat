package mtls

import (
	"context"
	"crypto/tls"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorObservationProducer is local to the process owning the actual
// connector keys. It reads native proof and checks its own live key/leaf;
// observing never reconciles a process, enrolls, signs or activates a leaf.
type ConnectorObservationProducer struct {
	pin         value.ConnectorObservationPin
	credentials *ConnectorProcessCredentials
	attester    app.ConnectorObservationProofReader
	workloads   app.ConnectorObservationWorkloadReader
	now         func() time.Time
}

func NewConnectorObservationProducer(pin value.ConnectorObservationPin, credentials *ConnectorProcessCredentials, attester app.ConnectorObservationProofReader, workloads app.ConnectorObservationWorkloadReader, now func() time.Time) (*ConnectorObservationProducer, error) {
	if !pin.Valid() || credentials == nil || !credentials.profile.Equal(pin.Profile) || attester == nil || workloads == nil || now == nil {
		return nil, value.ErrInvalid
	}
	return &ConnectorObservationProducer{pin.Clone(), credentials, attester, workloads, now}, nil
}

// This private entry is called only after current own-owner bootstrap proof on
// this same retained TLS connection. The stream owns the exact certificate sent
// in that handshake and the monotonic source-read ordinal. The exporter is
// derived here from the actual connection, never accepted from a peer field.
func (s *ConnectorObservationProducer) observe(ctx context.Context, state *tls.ConnectionState, leaf value.ConnectorCredentialCertificate, request value.OwnerObservationRequest, ordinal int) (contracts.ConnectorObservationReply, error) {
	var zero contracts.ConnectorObservationReply
	if s == nil || ctx == nil || ctx.Err() != nil || !request.Valid(s.now()) || request.RootID != s.pin.Profile.RootID || ordinal < 1 || ordinal > value.ConnectorObservationMaximumChecks || !leaf.Valid(s.now()) || leaf.Usage != "client" || leaf.Binding != s.pin.Profile.Binding {
		return zero, value.ErrDenied
	}
	channel, e := ownerObservationConnection(state, request)
	if e != nil {
		return zero, e
	}
	start := s.now()
	until := identity.Earlier(request.NotAfter, identity.Earlier(start.Add(5*time.Second), leaf.NotAfter))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	// Process shutdown cancels actual admitted native work; join the callback
	// before returning. This never turns cancellation into remote completion.
	joined := make(chan struct{})
	stopRoot := context.AfterFunc(s.credentials.root, func() { stop(); close(joined) })
	defer func() {
		if !stopRoot() {
			<-joined
		}
	}()
	keys, e := s.credentials.observationKeys(call, leaf)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, keys.runUntil)
	call, stopKeys := context.WithDeadline(call, until)
	defer stopKeys()
	attested, e := s.attester.ReadConnectorObservationProof(call, keys.request)
	proof := attested.Proof
	if e != nil || !attested.Matches(s.pin, s.now()) || proof.Process != keys.request.Process || proof.ClientKeyDigest != keys.keys[0] || proof.ServerKeyDigest != keys.keys[1] || s.credentials.verifyObservationKeys(keys, proof.Configuration) != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, proof.FreshUntil)
	call, stopProof := context.WithDeadline(call, until)
	defer stopProof()
	workload, e := s.workloads.ObserveConnectorWorkload(call, proof.Process, proof.Pod)
	if e != nil || !workload.Matches(s.pin, s.now()) || workload.Process != proof.Process || workload.Pod != proof.Pod || workload.ReplicaSetUID != proof.ReplicaSetUID {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, workload.FreshUntil)
	observed := start
	for _, at := range []time.Time{keys.observedAt, proof.ObservedAt, proof.Configuration.ObservedAt, workload.ObservedAt} {
		if observed.Before(at) {
			observed = at
		}
	}
	out := value.ConnectorObservation{Request: request, Ordinal: ordinal, ConnectionBinding: channel, Certificate: leaf, Source: attested.Source, Workload: workload, ObservedAt: observed, FreshUntil: until}
	// The snapshot is only a restrictive process/key/leaf veto. Native proof and
	// exact installed template remain independently current. Hub SQL49 registry
	// checks bracket fresh numbered replies before metadata and after its result.
	if call.Err() != nil || !out.Matches(s.pin, s.now()) || s.credentials.verifyObservationKeys(keys, proof.Configuration) != nil || s.credentials.observationKeysCurrent(call, keys) != nil {
		return zero, value.ErrUnavailable
	}
	return connectorObservationReplyWire(out, s.pin)
}
