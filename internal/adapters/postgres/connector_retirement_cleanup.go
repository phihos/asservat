package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectorRetirementCleanup uses the separately pinned cleanup login. It can
// close exact references and delete an independently retired ticket; it cannot
// admit an audit writer, verify provider absence or release an audit pair.
type ConnectorRetirementCleanup struct {
	ledger             *Ledger
	root, installation string
}

func NewConnectorRetirementCleanup(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*ConnectorRetirementCleanup, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ConnectorRetirementCleanup{ledger: l, root: root, installation: installation}, nil
}

// Closing the accepting reference permanently ends this ticket's admission.
// An already admitted audit writer remains separately charged and referenced.
func (s *ConnectorRetirementCleanup) CloseAdmission(ctx context.Context, ticketID string, current app.ConnectorRetirementCurrent) (bool, error) {
	return s.change(ctx, ticketID, current, func(ctx context.Context, q *custodydb.Queries) (bool, error) {
		return q.CloseConnectorRetirementAdmission(ctx, custodydb.CloseConnectorRetirementAdmissionParams{RootID: id(s.root), TicketID: id(ticketID)})
	})
}

// This only severs the business reference after the original write interval.
// The existing audit lifecycle still needs positive joined writer completion,
// or its separately qualified overdue path, and independent physical cleanup.
func (s *ConnectorRetirementCleanup) CloseWriterReference(ctx context.Context, ticketID string, current app.ConnectorRetirementCurrent) (bool, error) {
	return s.change(ctx, ticketID, current, func(ctx context.Context, q *custodydb.Queries) (bool, error) {
		return q.CloseConnectorRetirementWriterReference(ctx, custodydb.CloseConnectorRetirementWriterReferenceParams{RootID: id(s.root), TicketID: id(ticketID)})
	})
}

// DeleteTicket succeeds only after the original history-release instant,
// closed admission/references and exact audit/history retirement. Independent
// source-row backing remains reserved through the original retained end. False means
// no ticket was deleted; absence alone is never reported as verified cleanup.
func (s *ConnectorRetirementCleanup) DeleteTicket(ctx context.Context, ticketID string, current app.ConnectorRetirementCurrent) (bool, error) {
	return s.change(ctx, ticketID, current, func(ctx context.Context, q *custodydb.Queries) (bool, error) {
		return q.DeleteConnectorRetirementTicket(ctx, custodydb.DeleteConnectorRetirementTicketParams{RootID: id(s.root), TicketID: id(ticketID)})
	})
}
func (s *ConnectorRetirementCleanup) change(ctx context.Context, ticketID string, current app.ConnectorRetirementCurrent, run func(context.Context, *custodydb.Queries) (bool, error)) (bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(ticketID) || current.Proof != nil || !current.Valid(time.Now()) || current.Recovery.InstallationID != s.installation {
		return false, value.ErrUnavailable
	}
	bounded, stop := context.WithDeadline(ctx, current.Until)
	defer stop()
	var changed bool
	err := s.ledger.transaction(bounded, func(q *custodydb.Queries) error {
		var err error
		changed, err = run(bounded, q)
		if err != nil {
			return err
		}
		if bounded.Err() != nil || !current.Valid(time.Now()) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || bounded.Err() != nil || !current.Valid(time.Now()) {
		return false, value.ErrUnavailable
	}
	return changed, nil
}
