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
	"github.com/google/uuid"
)

// This distinct v2 producer accepts only the installed concrete native-operation
// port and actual process credentials. It cannot impersonate a legacy full
// source or attestation reader. Each stream's private channel owns one begin.
type ConnectorObservationOperationProducer struct {
	pin         value.ConnectorObservationPin
	credentials *ConnectorProcessCredentials
	native      app.ConnectorNativeObservationOperations
	now         func() time.Time
}

func NewConnectorObservationOperationProducer(pin value.ConnectorObservationPin, credentials *ConnectorProcessCredentials, native app.ConnectorNativeObservationOperations, now func() time.Time) (*ConnectorObservationOperationProducer, error) {
	if !pin.Valid() || credentials == nil || !credentials.profile.Equal(pin.Profile) || native == nil || now == nil {
		return nil, value.ErrInvalid
	}
	return &ConnectorObservationOperationProducer{pin.Clone(), credentials, native, now}, nil
}

type connectorProducedOperation struct {
	producer     *ConnectorObservationOperationProducer
	root         context.Context
	cancel       context.CancelFunc
	joinProcess  func()
	native       app.ConnectorNativeObservationOperation
	keys         connectorObservationKeys
	request      value.OwnerObservationRequest
	channel      artifact.Digest
	id           string
	mu           sync.Mutex
	closed, busy bool
	ordinal      int
	until        time.Time
	last         *value.ConnectorObservationOperationValue
	joined       sync.WaitGroup
	closeOnce    sync.Once
}

// streamRoot is the actual still-owned stream, not a per-frame call. The call
// remains linked through admission, then its callback is joined before returning
// the retained operation. Its original deadline remains a permanent cap. The
// channel must Close this operation on any later frame/delivery failure.
func (p *ConnectorObservationOperationProducer) begin(streamRoot, call context.Context, state *tls.ConnectionState, leaf value.ConnectorCredentialCertificate, request value.OwnerObservationRequest) (*connectorProducedOperation, error) {
	if p == nil || streamRoot == nil || call == nil || streamRoot.Err() != nil || call.Err() != nil || !request.Valid(p.now()) || request.RootID != p.pin.Profile.RootID || !leaf.Valid(p.now()) || leaf.Usage != "client" || leaf.Binding != p.pin.Profile.Binding {
		return nil, value.ErrInvalid
	}
	streamEnd, finite := streamRoot.Deadline()
	callEnd, callFinite := call.Deadline()
	if !finite || !callFinite || !p.now().Before(streamEnd) || streamEnd.After(p.now().Add(30*time.Second)) {
		return nil, value.ErrInvalid
	}
	channel, err := observationOperationConnection(state, request)
	if err != nil {
		return nil, err
	}
	until := identity.Earlier(request.NotAfter, identity.Earlier(streamEnd, identity.Earlier(callEnd, leaf.NotAfter)))
	root, cancel := context.WithDeadline(streamRoot, until)
	joinProcess := linkObservationCancellation(p.credentials.root, cancel)
	joinCall := linkObservationCancellation(call, cancel)
	keys, err := p.credentials.observationKeys(root, leaf)
	if err != nil {
		cancel()
		joinCall()
		joinProcess()
		return nil, value.ErrUnavailable
	}
	until = identity.Earlier(until, keys.runUntil)
	bounded, stopBound := context.WithDeadline(root, until)
	native, err := p.native.OpenConnectorObservationOperation(bounded, request, keys.request.Process)
	joinCall()
	if err != nil || native == nil || call.Err() != nil || bounded.Err() != nil || p.credentials.observationKeysCurrent(bounded, keys) != nil {
		cancel()
		stopBound()
		if native != nil {
			native.Close()
		}
		joinProcess()
		return nil, value.ErrUnavailable
	}
	return &connectorProducedOperation{producer: p, root: bounded, cancel: func() { cancel(); stopBound() }, joinProcess: joinProcess, native: native, keys: keys, request: request, channel: channel, id: uuid.NewString(), until: until}, nil
}

func (o *connectorProducedOperation) Close() {
	if o == nil {
		return
	}
	o.closeOnce.Do(func() {
		o.mu.Lock()
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		o.native.Close()
		o.joined.Wait()
		o.joinProcess()
	})
}

func (o *connectorProducedOperation) read(ctx context.Context, ordinal int) (contracts.ConnectorObservationOperationReply, error) {
	var zero contracts.ConnectorObservationOperationReply
	if o == nil {
		return zero, value.ErrInvalid
	}
	o.mu.Lock()
	end, finite := time.Time{}, false
	if ctx != nil {
		end, finite = ctx.Deadline()
	}
	if ctx == nil || !finite || ctx.Err() != nil || o.closed || o.busy || o.root.Err() != nil || ordinal != o.ordinal+1 || ordinal > 4 || !o.producer.now().Before(o.until) {
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	o.busy = true
	o.ordinal = ordinal
	o.until = identity.Earlier(o.until, end)
	until := o.until
	o.joined.Add(1)
	o.mu.Unlock()
	success := false
	defer func() {
		o.mu.Lock()
		o.busy = false
		if !success {
			o.closed = true
			o.cancel()
		}
		o.mu.Unlock()
		o.joined.Done()
	}()
	call, cancel := context.WithDeadline(o.root, until)
	joinCall := linkObservationCancellation(ctx, cancel)
	defer func() { cancel(); joinCall() }()
	if o.producer.credentials.observationKeysCurrent(call, o.keys) != nil {
		return zero, value.ErrUnavailable
	}
	native, err := o.native.Read(call, ordinal)
	out := value.ConnectorObservationOperationValue{Native: native, BracketID: o.id, ConnectionBinding: o.channel, Certificate: o.keys.leaf}
	out = restrictConnectorOperationValue(out, until)
	if err != nil || call.Err() != nil || ctx.Err() != nil || !out.Matches(o.producer.pin, o.request, ordinal, o.producer.now()) || out.Native.Workload.Process != o.keys.request.Process || o.producer.credentials.verifyObservationKeys(o.keys, out.Native.Source.Observation) != nil || o.producer.credentials.observationKeysCurrent(call, o.keys) != nil {
		return zero, value.ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.root.Err() != nil || call.Err() != nil || ctx.Err() != nil || o.last != nil && !out.Continues(*o.last) {
		return zero, value.ErrUnavailable
	}
	o.until = identity.Earlier(o.until, out.Until())
	out = restrictConnectorOperationValue(out, o.until)
	wire, err := connectorOperationReplyWire(out, o.producer.pin, o.producer.now())
	if err != nil {
		return zero, err
	}
	last := out.Clone()
	o.last = &last
	success = true
	return wire, nil
}
