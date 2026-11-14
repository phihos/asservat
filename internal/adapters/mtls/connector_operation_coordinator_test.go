package mtls

import (
	"context"
	"crypto/tls"
	"sync/atomic"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Actual process keys and mutual TLS; native/SQL and terminal stream are fixed
// synthetic component ports. This is not a framed/native route qualification.
type ownerOperationNativeFixture struct {
	facts                   value.OwnerObservationNativeFacts
	original, final, closed atomic.Int32
	finalHook               func(context.Context, *value.OwnerObservationNativeFacts) error
	originalHook            func(context.Context)
}

func (f *ownerOperationNativeFixture) Original(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	f.original.Add(1)
	if f.originalHook != nil {
		f.originalHook(ctx)
	}
	if ctx.Err() != nil || f.final.Load() != 0 || f.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return f.facts.Clone(), nil
}
func (f *ownerOperationNativeFixture) Final(ctx context.Context) (value.OwnerObservationNativeFacts, error) {
	if f.final.Add(1) != 1 || f.closed.Load() != 0 {
		return value.OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	v := f.facts.Clone()
	v.Final = true
	if f.finalHook != nil {
		if err := f.finalHook(ctx, &v); err != nil {
			return value.OwnerObservationNativeFacts{}, err
		}
	}
	return v, nil
}
func (f *ownerOperationNativeFixture) Close() { f.closed.Add(1) }

type operationCoordinatorFixture struct {
	f                                 *connectorPairFixture
	pin                               value.ConnectorObservationPin
	owner                             value.OwnerObservationPin
	server                            *OwnerCredentials
	registry                          app.OwnerCertificateRegistry
	regional                          *ConnectorProcessCredentials
	state                             tls.ConnectionState
	local                             ConnectorProcessObservation
	request                           value.ClusterObservationRequest
	mode                              string
	ctx                               context.Context
	native                            *ownerOperationNativeFixture
	regionalNative                    *connectorOperationNativeFixture
	operation                         *OwnerObservationOperation
	channel                           *ConnectorObservationOperationChannel
	hub                               *HubConnectorObservationOperation
	pairs, proofs, metadata, receipts int
	probeHook                         func(*contracts.ClusterObservationOperationProbe)
	pairHook                          func(int, *app.ConnectorObservationOperationRegistration)
	pairDeadlineHook                  func(context.Context, int)
}

func (x *operationCoordinatorFixture) ReadConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, source app.ConnectorObservationOperationSource, leaf value.ConnectorCredentialCertificate, n int) (app.ConnectorObservationOperationRegistration, error) {
	x.pairs++
	if x.pairDeadlineHook != nil {
		x.pairDeadlineHook(ctx, n)
	}
	if leaf != x.local.Registration.Certificate {
		return app.ConnectorObservationOperationRegistration{}, value.ErrDenied
	}
	var last value.ConnectorObservationOperationValue
	for i := n; i < n+2; i++ {
		v, err := source.ReadConnectorObservationValue(ctx, i)
		if err != nil {
			return app.ConnectorObservationOperationRegistration{}, err
		}
		last = v
	}
	out := app.ConnectorObservationOperationRegistration{Registration: x.local.Registration, Last: last}
	out.Registration.FreshUntil = identity.Earlier(out.Registration.FreshUntil, last.Until())
	if x.pairHook != nil {
		x.pairHook(n, &out)
	}
	if x.mode == "sql-revoked-final" && n == 3 {
		return out, value.ErrUnavailable
	}
	return out, nil
}
func (x *operationCoordinatorFixture) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	x.metadata++
	if x.proofs != 2 || x.native.final.Load() != 0 || x.regionalNative.reads.Load() != 2 {
		return value.ClusterObservationResult{}, value.ErrDenied
	}
	digest, err := app.ClusterObservationRequestDigest(r)
	if err != nil {
		return value.ClusterObservationResult{}, err
	}
	end, _ := ctx.Deadline()
	return value.ClusterObservationResult{RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: r.Purpose, RequestDigest: digest, Interval: value.ClusterObservationInterval{ObservedAt: x.f.clock(), FreshUntil: end}, Namespaces: &value.ClusterNamespaceCandidatePage{ResourceVersion: "1", Items: []cfg.NamespaceRef{}}}, nil
}
