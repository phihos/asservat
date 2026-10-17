package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This v2 reader has the same fixed EXECUTE-only SQL49 role/query as the v1
// registry. Its explicit source port supplies fresh source values under the
// original two native brackets, not four new full native attestations.
type ConnectorObservationOperationRegistry struct {
	ledger *Ledger
	pin    value.ConnectorObservationPin
}

var _ app.ConnectorObservationOperationRegistry = (*ConnectorObservationOperationRegistry)(nil)

func NewConnectorObservationOperationRegistry(ctx context.Context, pool *pgxpool.Pool, pin value.ConnectorObservationPin) (*ConnectorObservationOperationRegistry, error) {
	if ctx == nil || ctx.Err() != nil || !pin.Valid() {
		return nil, value.ErrUnavailable
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ConnectorObservationOperationRegistry{ledger: l, pin: pin.Clone()}, nil
}

func (s *ConnectorObservationOperationRegistry) ReadConnectorObservationOperation(ctx context.Context, request value.OwnerObservationRequest, source app.ConnectorObservationOperationSource, leaf value.ConnectorCredentialCertificate, ordinal int) (app.ConnectorObservationOperationRegistration, error) {
	if s == nil || s.ledger == nil {
		return app.ConnectorObservationOperationRegistration{}, value.ErrUnavailable
	}
	return s.readOperation(ctx, request, source, leaf, ordinal, custodydb.New(s.ledger.pool))
}

// The query seam is private and fixed to the generated SQL49 method. Production
// always constructs it from the original ledger above; it is not an authority
// callback, configurable credential, alternate SQL statement or public input.
func (s *ConnectorObservationOperationRegistry) readOperation(ctx context.Context, request value.OwnerObservationRequest, source app.ConnectorObservationOperationSource, leaf value.ConnectorCredentialCertificate, ordinal int, query connectorActivatedLeafQuery) (app.ConnectorObservationOperationRegistration, error) {
	var zero app.ConnectorObservationOperationRegistration
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !s.pin.Valid() || !request.Valid(time.Now()) || request.RootID != s.pin.Profile.RootID || source == nil || query == nil || ordinal != 1 && ordinal != 3 || !leaf.Valid(time.Now()) || leaf.Usage != "client" || leaf.Binding != s.pin.Profile.Binding {
		return zero, value.ErrUnavailable
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(deadline, identity.Earlier(request.NotAfter, leaf.NotAfter))
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	first, err := source.ReadConnectorObservationValue(call, ordinal)
	if err != nil || !first.Matches(s.pin, request, ordinal, time.Now()) || first.Certificate != leaf || call.Err() != nil {
		return zero, value.ErrUnavailable
	}
	first = first.Clone()
	until = identity.Earlier(until, first.Until())
	bounded, stop := context.WithDeadline(call, until)
	defer stop()
	registered, err := readConnectorActivatedLeaf(bounded, query, s.pin.Profile, leaf.Binding, leaf.Usage, leaf.Digest, first.Native.Source, until)
	if err != nil || registered.Certificate != leaf || registered.Process != first.Native.Workload.Process {
		return zero, value.ErrUnavailable
	}
	// SQL's returned current interval can shorten the last actual source read;
	// it can never replace it. No second source call follows failed SQL.
	until = identity.Earlier(until, registered.FreshUntil)
	final, stopFinal := context.WithDeadline(bounded, until)
	defer stopFinal()
	last, err := source.ReadConnectorObservationValue(final, ordinal+1)
	if err != nil || !last.Matches(s.pin, request, ordinal+1, time.Now()) || !last.Continues(first) || !first.Matches(s.pin, request, ordinal, time.Now()) || final.Err() != nil {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, last.Until())
	registered.FreshUntil = identity.Earlier(registered.FreshUntil, until)
	if !registered.Valid(time.Now()) || !time.Now().Before(until) {
		return zero, value.ErrUnavailable
	}
	return app.ConnectorObservationOperationRegistration{Registration: registered, Last: last.Clone()}, nil
}
