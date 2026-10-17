package fleet

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorRetirementProposal derives an immutable proposed ticket from one
// original accepting intent and the independently selected retained cohort.
// It has no I/O or authority. The SQL admission wrapper independently checks
// complete membership, source/backing, capacity and the original request dates.
// Unknown committed admission replies must first look up their original event;
// this constructor is not an idempotency or replacement protocol.
func ConnectorRetirementProposal(in audit.OperationIntent, ticketID string, cohort ConnectorRetirementCohort, backing ConnectorIdentityBacking, backingDigest, accountDigest artifact.Digest) (audit.ConnectorRetirementTicket, error) {
	var zero audit.ConnectorRetirementTicket
	if !authorization.UUID(ticketID) || !authorization.UUID(in.ID) || in.RootID != cohort.RootID || in.Process == nil || !in.Process.Valid() || in.Name != "connector_process_enrollment" && in.Name != "connector_backing_acceptance" || in.AccountVersion != backing.AccountVersion || backing.Policy.History == nil || backing.Policy.History.Layout != audit.ConnectorRetirementHistoryLayout {
		return zero, value.ErrUnavailable
	}
	p := backing.Clone().Policy
	p.ValidUntil = p.ValidUntil.UTC()
	// This public policy-image digest binds a derived purpose identifier, not a
	// provider permission. No credential, complete source payload or fresh
	// observation enters the persistent ticket.
	raw, e := json.Marshal(struct {
		TicketID, AcceptanceID string
		Policy                 audit.OperationLifecyclePolicy
		BackingDigest          artifact.Digest
	}{ticketID, in.ID, p, backingDigest})
	if e != nil || len(raw) > 16<<10 {
		return zero, value.ErrUnavailable
	}
	policyDigest := sha256.Sum256(append([]byte("asservat-connector-retirement-policy/v1\x00"), raw...))
	originalPurge := in.RetainUntil.Add(-time.Duration(2*p.BackupHorizonSeconds+3*p.CleanupBudgetSeconds+p.ProofWindowSeconds) * time.Second)
	return (ConnectorRetirementPlan{TicketID: ticketID, AcceptanceID: in.ID, OriginalActor: *in.Process, Cohort: cohort, Backing: backing.Clone(), BackingDigest: backingDigest, AccountDigest: accountDigest, PolicyDigest: artifact.Digest(policyDigest), AcceptanceCreatedAt: in.CreatedAt, AcceptanceRetainUntil: in.RetainUntil, AcceptancePurgeAt: originalPurge}).Ticket()
}
