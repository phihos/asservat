package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvents appends audit rows (REQ-AUT-005).
type AuditEvents struct{ pool *pgxpool.Pool }

func NewAuditEvents(pool *pgxpool.Pool) (*AuditEvents, error) {
	if pool == nil {
		return nil, app.ErrUnavailable
	}
	return &AuditEvents{pool: pool}, nil
}

func (s *AuditEvents) Record(ctx context.Context, e value.Event) error {
	if s == nil || !e.Valid() {
		return app.ErrUnavailable
	}
	if InsertAuditEvent(ctx, custodydb.New(s.pool), e) != nil {
		return app.ErrUnavailable
	}
	return nil
}

// InsertAuditEvent writes e with q, so an effect transaction can pass its own
// queries and commit the row with its effect.
func InsertAuditEvent(ctx context.Context, q *custodydb.Queries, e value.Event) error {
	if !e.Valid() {
		return app.ErrUnavailable
	}
	p := custodydb.InsertAuditEventParams{EventID: id(e.ID), OperationID: id(e.OperationID), Kind: e.Kind, Operation: e.Operation,
		Issuer: e.Actor.Issuer, Subject: e.Actor.Subject, ClientID: e.Actor.ClientID, IdentityType: string(e.Actor.Kind),
		Status: e.Status, Reason: e.Reason, Effect: e.Effect, CaseIds: nonNil(e.CaseIDs), ArtifactIds: nonNil(e.ArtifactIDs),
		CaptureIds: nonNil(e.CaptureIDs), ShareIds: nonNil(e.ShareIDs), GrantIds: nonNil(e.GrantIDs), OutputBytes: e.OutputBytes}
	if e.Effect == "" {
		p.Effect = "none"
	}
	if e.InputDigest != nil {
		p.InputDigest = e.InputDigest[:]
	}
	if e.OutputDigest != nil {
		p.OutputDigest = e.OutputDigest[:]
	}
	if e.ReservationID != "" {
		p.ReservationID = id(e.ReservationID)
	}
	return q.InsertAuditEvent(ctx, p)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
