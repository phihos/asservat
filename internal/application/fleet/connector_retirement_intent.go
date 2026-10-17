package fleet

import (
	"encoding/json"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorRetirementIntent prepares a single immutable audit image. It neither
// consumes a ticket nor fences a profile. The purpose-specific SQL transaction
// independently joins the original accepted ticket, complete current source
// (when explicit), current role/recovery and exact original admission interval.
// Retries read their committed image; they never call this to replace an
// uncertain previously admitted intent or move its dates.
func ConnectorRetirementIntent(ticket audit.ConnectorRetirementTicket, cause string, retiring *audit.ConnectorRetiringSource, traceID string, start, until time.Time, mac *auditapp.OperationMAC) (audit.OperationIntent, error) {
	var zero audit.OperationIntent
	if mac == nil || !ticket.CanStart(start, until, start) || mac.AccountVersion() != ticket.AccountVersion {
		return zero, value.ErrUnavailable
	}
	_, digest, e := CanonicalConnectorRetirementTicket(ticket)
	if e != nil {
		return zero, e
	}
	origin := audit.ConnectorRetirementOrigin{Ticket: ticket.Clone(), TicketDigest: digest, Cause: cause, RetiringSource: retiring}.Clone()
	input, e := json.Marshal(origin)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	inputDigest, e := mac.Digest("connector-retirement/v1", input)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	in := audit.OperationIntent{
		ID: ticket.ID, RootID: ticket.RootID, TraceID: traceID,
		Name: "connector_retirement", InputFormat: "connector-retirement/v1",
		MACVersion: mac.Version(), AccountVersion: ticket.AccountVersion,
		PrincipalDigest: ticket.PrincipalDigest, InputDigest: inputDigest,
		CreatedAt: start, RequestUntil: until,
		WriteUntil:  identity.Earlier(start.Add(30*time.Second), ticket.ConsumeUntil),
		RetainUntil: ticket.RetainUntil, RetirementOrigin: &origin,
	}
	bound, e := auditapp.BindOperationLifecycle(in, ticket.Policy)
	if e != nil || !bound.Valid() || bound.Lifecycle == nil || !bound.Lifecycle.OriginalPurgeAt.Equal(ticket.OriginalPurgeAt()) {
		return zero, value.ErrUnavailable
	}
	return bound, nil
}
