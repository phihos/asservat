package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Fixed v2 bound: insert, activate, supersede, restrict, admit, close admission,
// close writer reference, delete, plus the profile fence and its final unlink.
// It is independent of the refundable unused pair reservation.
const ConnectorRetirementTicketTransitions int64 = 10

// ConnectorRetirementCohort is minimized historical accepted profile data. It
// contains no observation deadline or peer-specific complete source digest:
// another peer's root-wide backing acceptance cannot invent either. SQL derives
// it from the exact retained profile under the root lock. A current operation
// must still read and check that peer's complete protected source separately.
type ConnectorRetirementCohort struct {
	RootID                          string
	Binding                         value.PeerBinding
	Behavior                        identity.Revision
	ServingSlots, RetainedProcesses int
	BackingRevision                 int64
	BackingDigest                   artifact.Digest
}

func (c ConnectorRetirementCohort) Valid() bool {
	return authorization.UUID(c.RootID) && c.Binding.Valid() && c.Binding.Role == value.ConnectorPeer && c.Behavior.Valid() && authorization.UUID(c.Behavior.UID) && c.ServingSlots >= 1 && c.ServingSlots <= 16 && c.RetainedProcesses >= c.ServingSlots+1 && c.RetainedProcesses <= 256 && c.BackingRevision >= 1 && c.BackingRevision <= 1<<60 && c.BackingDigest != (artifact.Digest{})
}

// ConnectorRetirementPlan is private proposed reservation data. The exact
// ticket must be persisted, charged and included in the acceptance's immutable
// input before either encrypted acknowledgement; this helper grants nothing.
type ConnectorRetirementPlan struct {
	TicketID, AcceptanceID                                        string
	OriginalActor                                                 audit.OperationConnectorProcessActor
	Cohort                                                        ConnectorRetirementCohort
	Backing                                                       ConnectorIdentityBacking
	BackingDigest                                                 artifact.Digest
	AccountDigest                                                 artifact.Digest
	PolicyDigest                                                  artifact.Digest
	AcceptanceCreatedAt, AcceptanceRetainUntil, AcceptancePurgeAt time.Time
}

func (p ConnectorRetirementPlan) Ticket() (audit.ConnectorRetirementTicket, error) {
	var zero audit.ConnectorRetirementTicket
	c, b := p.Cohort, p.Backing
	if !authorization.UUID(p.TicketID) || !authorization.UUID(p.AcceptanceID) || p.TicketID == p.AcceptanceID || p.PolicyDigest == (artifact.Digest{}) || !p.OriginalActor.Valid() || !c.Valid() || !b.supportsProcessLimits(c.ServingSlots, c.RetainedProcesses) || b.Policy.History.Layout != audit.ConnectorRetirementHistoryLayout || b.Policy.RootID != c.RootID || b.Policy.InstallationID != c.Binding.InstallationID || p.BackingDigest == (artifact.Digest{}) || p.OriginalActor.Process.Binding.InstallationID != c.Binding.InstallationID || p.OriginalActor.Process.Binding.IssuerEpoch != c.Binding.IssuerEpoch || p.AccountDigest == (artifact.Digest{}) || !p.AcceptanceRetainUntil.Equal(p.AcceptanceCreatedAt.Add(time.Duration(b.RetainedSeconds)*time.Second)) {
		return zero, value.ErrUnavailable
	}
	// The initial ticket uses the exact accepted backing; a successor can only
	// propose the next revision. Neither case changes historical source fields.
	if b.Policy.BackingRevision == c.BackingRevision {
		if p.BackingDigest != c.BackingDigest {
			return zero, value.ErrUnavailable
		}
	} else if b.Policy.BackingRevision != c.BackingRevision+1 || p.BackingDigest == c.BackingDigest {
		return zero, value.ErrUnavailable
	}
	policy := b.Clone().Policy
	policy.PolicyID = p.TicketID
	policy.PolicyDigest = p.PolicyDigest
	purge := p.AcceptanceRetainUntil.Add(-time.Duration(2*policy.BackupHorizonSeconds+3*policy.CleanupBudgetSeconds+policy.ProofWindowSeconds) * time.Second)
	policy.ValidUntil = purge.Add(-30 * time.Second)
	t := audit.ConnectorRetirementTicket{ID: p.TicketID, RootID: b.Policy.RootID, AcceptanceID: p.AcceptanceID, Binding: c.Binding, OriginalActor: p.OriginalActor, Behavior: c.Behavior, ServingSlots: c.ServingSlots, RetainedProcesses: c.RetainedProcesses, BackingRevision: b.Policy.BackingRevision, BackingDigest: p.BackingDigest, AccountVersion: b.AccountVersion, PrincipalDigest: p.AccountDigest, ReservedAt: p.AcceptanceCreatedAt, AdmissionUntil: b.Policy.ValidUntil, ConsumeUntil: policy.ValidUntil, RetainUntil: p.AcceptanceRetainUntil, OriginalAcceptancePurgeAt: p.AcceptancePurgeAt, Policy: policy}
	if !t.Valid() {
		return zero, value.ErrUnavailable
	}
	return t, nil
}

// RetirementTicketCeiling covers the initial profile generation and every
// candidate generation allowed by the independently finite source budget.
// It is an upper bound for reserved plus admitted plus retained tombstones,
// never a source of capacity. SQL must reserve its complete pair/row/WAL cost.
func (b ConnectorIdentityBacking) RetirementTicketCeiling() (int64, bool) {
	if !b.Valid() {
		return 0, false
	}
	perProfile := b.SourceTransitionLimit + 1
	// Both factors are already bounded (4096 and 1000001 respectively).
	return b.ProfileLimit * perProfile, true
}

// SupportsRetirementDeployment includes the distinct initially reserved ticket
// and every retained successor before any ordinary pair can be admitted. The
// fixed pair qualification and SQL reservation still need independent acceptance.
func (b ConnectorIdentityBacking) SupportsRetirementDeployment(d value.ConnectorDeployment) bool {
	return b.Valid() && b.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout && b.SupportsDeployment(d)
}
