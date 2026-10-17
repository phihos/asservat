package postgres

import (
	"context"
	"errors"
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
	if err != nil {
		return zero, registryStep("first-read", err)
	}
	if !first.Matches(s.pin, request, ordinal, time.Now()) || first.Certificate != leaf || call.Err() != nil {
		return zero, registryStep(expiredStep(first, "first"), nil)
	}
	first = first.Clone()
	until = identity.Earlier(until, first.Until())
	bounded, stop := context.WithDeadline(call, until)
	defer stop()
	registered, err := readConnectorActivatedLeaf(bounded, query, s.pin.Profile, leaf.Binding, leaf.Usage, leaf.Digest, first.Native.Source, until)
	if err != nil || registered.Certificate != leaf || registered.Process != first.Native.Workload.Process {
		return zero, registryStep("leaf", err)
	}
	// SQL's returned current interval can shorten the last actual source read;
	// it can never replace it. No second source call follows failed SQL.
	until = identity.Earlier(until, registered.FreshUntil)
	final, stopFinal := context.WithDeadline(bounded, until)
	defer stopFinal()
	last, err := source.ReadConnectorObservationValue(final, ordinal+1)
	switch {
	case err != nil:
		return zero, registryStep("last-read", err)
	case !last.Matches(s.pin, request, ordinal+1, time.Now()):
		return zero, registryStep(expiredStep(last, "last"), nil)
	case !last.Continues(first):
		return zero, registryStep("continues", nil)
	case !first.Matches(s.pin, request, ordinal, time.Now()):
		return zero, registryStep(expiredStep(first, "first-again"), nil)
	case final.Err() != nil:
		return zero, registryStep("deadline", nil)
	}
	until = identity.Earlier(until, last.Until())
	registered.FreshUntil = identity.Earlier(registered.FreshUntil, until)
	if !registered.Valid(time.Now()) || !time.Now().Before(until) {
		return zero, registryStep("valid", nil)
	}
	return app.ConnectorObservationOperationRegistration{Registration: registered, Last: last.Clone()}, nil
}

// expiredStep labels a refused value "-expired" when its observed bounds have
// passed, otherwise "-match". It only names an already decided refusal.
func expiredStep(v value.ConnectorObservationOperationValue, name string) string {
	if !time.Now().Before(v.Until()) {
		return name + "-expired"
	}
	return name + "-match"
}

// registryStep names the fixed registry check that refused, for operator
// diagnostics (FixedStep); it always matches value.ErrUnavailable.
type registryStepError struct {
	step string
	err  error
}

func registryStep(step string, cause error) error {
	return &registryStepError{step, errors.Join(value.ErrUnavailable, cause)}
}

func (e *registryStepError) Error() string { return e.step }
func (e *registryStepError) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *registryStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
