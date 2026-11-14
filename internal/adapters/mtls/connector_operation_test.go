package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Actual process-owned keys and mutual TLS/h2 exporter; native source and SQL
// registration contents are explicit synthetic component fixtures. These tests
// do not qualify native APIs, the complete stream or installed availability.
type connectorOperationNativeFixture struct {
	f                            *connectorPairFixture
	pin                          value.ConnectorObservationPin
	opens, reads, finals, closes atomic.Int32
	openHook                     func(context.Context)
	readHook                     func(context.Context, int, *value.ConnectorObservationNativeValue) error
}
type connectorOperationNativeHandle struct {
	f            *connectorOperationNativeFixture
	root         context.Context
	cancel       context.CancelFunc
	request      value.OwnerObservationRequest
	process      value.ConnectorProcessIdentity
	start, until time.Time
	once         sync.Once
}

func (f *connectorOperationNativeFixture) OpenConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, p value.ConnectorProcessIdentity) (app.ConnectorNativeObservationOperation, error) {
	f.opens.Add(1)
	root, cancel := context.WithCancel(ctx)
	end, _ := ctx.Deadline()
	o := &connectorOperationNativeHandle{f, root, cancel, r, p, f.f.clock(), identity.Earlier(end, r.NotAfter), sync.Once{}}
	if f.openHook != nil {
		f.openHook(ctx)
	}
	return o, nil
}
func (o *connectorOperationNativeHandle) Close() { o.once.Do(func() { o.f.closes.Add(1); o.cancel() }) }
func (o *connectorOperationNativeHandle) Read(ctx context.Context, n int) (value.ConnectorObservationNativeValue, error) {
	o.f.reads.Add(1)
	if n == 4 {
		o.f.finals.Add(1)
	}
	if o.root.Err() != nil {
		return value.ConnectorObservationNativeValue{}, value.ErrUnavailable
	}
	source, _ := o.f.f.ReadConnectorIdentitySource(ctx)
	end, _ := ctx.Deadline()
	o.until = identity.Earlier(o.until, end)
	source.Observation.FreshUntil = o.until
	w := value.ConnectorObservationWorkload{Process: o.process, Pod: "connector-1", ReplicaSetUID: ownerTestID, TemplateDigest: o.f.pin.TemplateDigest, ImageDigest: o.f.pin.ImageDigest, ProtectionDigest: o.f.pin.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: o.start, FreshUntil: o.until}
	v := value.ConnectorObservationNativeValue{Request: o.request, Ordinal: n, Source: source, Workload: w, NativeStartedAt: o.start, NativeUntil: o.until, ValueObservedAt: o.f.f.clock(), Final: n == 4}
	if o.f.readHook != nil {
		if err := o.f.readHook(ctx, n, &v); err != nil {
			return value.ConnectorObservationNativeValue{}, err
		}
	}
	return v, nil
}

type connectorOperationTestExchange func(context.Context, int) (contracts.ConnectorObservationOperationReply, error)

func (f connectorOperationTestExchange) ReadConnectorObservationOperation(ctx context.Context, n int) (contracts.ConnectorObservationOperationReply, error) {
	return f(ctx, n)
}

type connectorOperationFixture struct {
	f           *connectorPairFixture
	credentials *ConnectorProcessCredentials
	pin         value.ConnectorObservationPin
	owner       value.OwnerObservationPin
	local       ConnectorProcessObservation
	root        context.Context
	state       *tls.ConnectionState
	request     value.OwnerObservationRequest
	native      *connectorOperationNativeFixture
	producer    *ConnectorObservationOperationProducer
}

func (f *connectorOperationFixture) source(t *testing.T, exchange connectorOperationExchange) *RemoteConnectorObservationOperationSource {
	t.Helper()
	s, err := NewRemoteConnectorObservationOperationSource(f.root, f.pin, f.owner, f.request, f.state, exchange, f.f.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func operationTestRegistration(f *connectorOperationFixture, last value.ConnectorObservationOperationValue) app.ConnectorObservationOperationRegistration {
	r := f.local.Registration
	r.FreshUntil = identity.Earlier(r.FreshUntil, last.Until())
	return app.ConnectorObservationOperationRegistration{Registration: r, Last: last.Clone()}
}
