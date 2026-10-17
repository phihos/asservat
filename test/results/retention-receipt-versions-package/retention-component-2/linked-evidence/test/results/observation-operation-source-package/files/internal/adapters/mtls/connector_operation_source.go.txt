package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Only a concrete v2 stream implements this closed four-number exchange. It
// performs actual I/O and joins its native proof/write/read before returning.
type connectorOperationExchange interface {
	ReadConnectorObservationOperation(context.Context, int) (contracts.ConnectorObservationOperationReply, error)
}

// RemoteConnectorObservationOperationSource is private to one actual stream and
// one query. The same instance spans both SQL49 reads. A wire correlation cannot
// manufacture it; it implements no legacy full-source interface.
type RemoteConnectorObservationOperationSource struct {
	pin                 value.ConnectorObservationPin
	request             value.OwnerObservationRequest
	state               tls.ConnectionState
	channel             artifact.Digest
	leaf                value.ConnectorCredentialCertificate
	verifier            *ConnectorCredentialVerifier
	exchange            connectorOperationExchange
	now                 func() time.Time
	root                context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	closed, busy        bool
	ordinal, registered int
	until               time.Time
	last                *value.ConnectorObservationOperationValue
	firstRegistration   *app.ConnectorObservationOperationRegistration
	joined              sync.WaitGroup
}

var _ app.ConnectorObservationOperationSource = (*RemoteConnectorObservationOperationSource)(nil)

func NewRemoteConnectorObservationOperationSource(ctx context.Context, pin value.ConnectorObservationPin, owner value.OwnerObservationPin, request value.OwnerObservationRequest, state *tls.ConnectionState, exchange connectorOperationExchange, now func() time.Time) (*RemoteConnectorObservationOperationSource, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !pin.Valid() || !owner.Valid() || !request.Valid(now()) || request.RootID != pin.Profile.RootID || request.RootID != owner.RootID || pin.Profile.Binding.InstallationID != owner.Pool.InstallationID || exchange == nil {
		return nil, value.ErrInvalid
	}
	end, finite := ctx.Deadline()
	if !finite || !now().Before(end) {
		return nil, value.ErrInvalid
	}
	common, err := OwnerBootstrapServerName(owner.Pool)
	if err != nil || state == nil || state.ServerName != common {
		return nil, value.ErrDenied
	}
	channel, err := observationOperationConnection(state, request)
	if err != nil {
		return nil, err
	}
	snapshot, err := snapshotOwnerTLS(state)
	if err != nil {
		return nil, err
	}
	verifier, err := NewConnectorCredentialVerifier(pin.Profile, now)
	if err != nil {
		return nil, err
	}
	leaf, err := verifier.verify(snapshot.PeerCertificates, "client", verifier.clientRoots)
	if err != nil || leaf.Binding != pin.Profile.Binding {
		return nil, value.ErrDenied
	}
	until := identity.Earlier(end, identity.Earlier(request.NotAfter, leaf.NotAfter))
	root, cancel := context.WithDeadline(ctx, until)
	return &RemoteConnectorObservationOperationSource{pin: pin.Clone(), request: request, state: snapshot, channel: channel, leaf: leaf, verifier: verifier, exchange: exchange, now: now, root: root, cancel: cancel, until: until}, nil
}

func (s *RemoteConnectorObservationOperationSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
}

func (s *RemoteConnectorObservationOperationSource) ReadConnectorObservationValue(ctx context.Context, ordinal int) (value.ConnectorObservationOperationValue, error) {
	var zero value.ConnectorObservationOperationValue
	if s == nil {
		return zero, value.ErrInvalid
	}
	s.mu.Lock()
	end, finite := time.Time{}, false
	if ctx != nil {
		end, finite = ctx.Deadline()
	}
	if ctx == nil || !finite || ctx.Err() != nil || s.closed || s.busy || s.root.Err() != nil || ordinal != s.ordinal+1 || ordinal > 4 || ordinal == 3 && s.registered != 2 || !s.now().Before(s.until) {
		s.closed = true
		s.cancel()
		s.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	s.ordinal = ordinal
	s.busy = true
	s.until = identity.Earlier(s.until, end)
	until := s.until
	s.joined.Add(1)
	s.mu.Unlock()
	success := false
	defer func() {
		s.mu.Lock()
		s.busy = false
		if !success {
			s.closed = true
			s.cancel()
		}
		s.mu.Unlock()
		s.joined.Done()
	}()
	call, cancel := context.WithDeadline(s.root, until)
	joinCall := linkObservationCancellation(ctx, cancel)
	defer func() { cancel(); joinCall() }()
	before, err := s.verifier.verify(s.state.PeerCertificates, "client", s.verifier.clientRoots)
	if err != nil || before != s.leaf {
		return zero, value.ErrUnavailable
	}
	wire, err := s.exchange.ReadConnectorObservationOperation(call, ordinal)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	out, err := parseConnectorOperationReply(wire, s.pin, s.leaf, s.request, ordinal, s.channel, s.now())
	if err != nil {
		return zero, value.ErrUnavailable
	}
	after, err := s.verifier.verify(s.state.PeerCertificates, "client", s.verifier.clientRoots)
	if err != nil || after != before || call.Err() != nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	out = restrictConnectorOperationValue(out, until)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root.Err() != nil || call.Err() != nil || ctx.Err() != nil || !out.Matches(s.pin, s.request, ordinal, s.now()) || s.last != nil && !out.Continues(*s.last) {
		return zero, value.ErrUnavailable
	}
	s.until = identity.Earlier(s.until, out.Until())
	last := out.Clone()
	s.last = &last
	success = true
	return out.Clone(), nil
}

// AcceptRegistration binds a returned SQL49 result to this source's exact last
// actual value. Ordinal3 cannot begin until pair1/2 was accepted. Final pair3/4
// must continue that same stored source instance, original leaf and SQL process.
// The concrete SQL adapter still owns current SQL authority; this is a veto.
func (s *RemoteConnectorObservationOperationSource) AcceptRegistration(ctx context.Context, r app.ConnectorObservationOperationRegistration) (time.Time, error) {
	if s == nil {
		return time.Time{}, value.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deny := func() (time.Time, error) { s.closed = true; s.cancel(); return time.Time{}, value.ErrUnavailable }
	if ctx == nil || ctx.Err() != nil || s.closed || s.busy || s.root.Err() != nil || s.last == nil || s.ordinal != 2 && s.ordinal != 4 || s.registered == s.ordinal || !s.now().Before(s.until) {
		return deny()
	}
	end, finite := ctx.Deadline()
	if !finite {
		return deny()
	}
	last := s.last
	if !r.Last.Matches(s.pin, s.request, s.ordinal, s.now()) || !r.Last.Continues(*last) || !last.Continues(r.Last) || r.Last.Native.Ordinal != last.Native.Ordinal || r.Last.Native.Final != last.Native.Final || !r.Last.Native.ValueObservedAt.Equal(last.Native.ValueObservedAt) || !r.Registration.Valid(s.now()) || r.Registration.Certificate != s.leaf || r.Registration.Process != last.Native.Workload.Process || r.Registration.Revision != last.Native.Source.Observation.Profile.Revision || r.Registration.FreshUntil.After(r.Last.Until()) {
		return deny()
	}
	if s.ordinal == 4 {
		first := s.firstRegistration
		if first == nil || !r.FinalMatches(s.pin, s.request, s.now()) || !r.Last.Continues(first.Last) || r.Registration.Certificate != first.Registration.Certificate || r.Registration.Process != first.Registration.Process || r.Registration.Revision != first.Registration.Revision {
			return deny()
		}
	}
	s.until = identity.Earlier(s.until, identity.Earlier(end, r.Registration.FreshUntil))
	if !s.now().Before(s.until) {
		return deny()
	}
	s.registered = s.ordinal
	if s.ordinal == 2 {
		copy := r
		copy.Last = r.Last.Clone()
		s.firstRegistration = &copy
	}
	return s.until, nil
}
