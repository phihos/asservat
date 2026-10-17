package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorRetirementTicket is the immutable, separately reserved restrictive
// allowance bound by an original acknowledged acceptance. Valid checks shape
// and original dates only. Current SQL role/recovery, exact ticket state and the
// acknowledged acceptance still decide whether it can be consumed.
//
// OriginalActor is historical provenance. It is deliberately not a
// ConnectorProcessProof, AuthenticatedPeer or CurrentIdentity.
type ConnectorRetirementTicket struct {
	ID, RootID, AcceptanceID        string
	Binding                         fleet.PeerBinding
	OriginalActor                   OperationConnectorProcessActor
	Behavior                        identity.Revision
	ServingSlots, RetainedProcesses int
	BackingRevision                 int64
	BackingDigest                   artifact.Digest
	AccountVersion                  string
	PrincipalDigest                 artifact.Digest
	ReservedAt, AdmissionUntil      time.Time
	ConsumeUntil, RetainUntil       time.Time
	OriginalAcceptancePurgeAt       time.Time
	Policy                          OperationLifecyclePolicy
}

func (t ConnectorRetirementTicket) OriginalPurgeAt() time.Time {
	p := t.Policy
	return t.RetainUntil.Add(-time.Duration(2*p.BackupHorizonSeconds+3*p.CleanupBudgetSeconds+p.ProofWindowSeconds) * time.Second)
}

func (t ConnectorRetirementTicket) Valid() bool {
	p := t.Policy
	if !authorization.UUID(t.ID) || !authorization.UUID(t.RootID) || !authorization.UUID(t.AcceptanceID) || t.ID == t.AcceptanceID || !t.Binding.Valid() || t.Binding.Role != fleet.ConnectorPeer || !t.OriginalActor.Valid() || t.OriginalActor.Process.Binding.InstallationID != t.Binding.InstallationID || t.OriginalActor.Process.Binding.IssuerEpoch != t.Binding.IssuerEpoch || !t.Behavior.Valid() || !authorization.UUID(t.Behavior.UID) || t.BackingRevision < 1 || t.BackingRevision > 1<<60 || t.BackingDigest == (artifact.Digest{}) || !identity.Text(t.AccountVersion, 64) || t.PrincipalDigest == (artifact.Digest{}) || !p.CertificateVerificationBacked() || p.History.Layout != ConnectorRetirementHistoryLayout || p.Lane != "identity" || p.RootID != t.RootID || p.InstallationID != t.Binding.InstallationID || p.BackingRevision != t.BackingRevision || p.PolicyID != t.ID || p.OverdueTerminal != OperationOverdueTerminal {
		return false
	}
	for _, v := range []time.Time{t.ReservedAt, t.AdmissionUntil, t.ConsumeUntil, t.RetainUntil, t.OriginalAcceptancePurgeAt} {
		if !microTime(v) {
			return false
		}
	}
	if t.ServingSlots < 1 || t.ServingSlots > 16 || t.RetainedProcesses < t.ServingSlots+1 || t.RetainedProcesses > 256 {
		return false
	}
	purge := t.OriginalPurgeAt()
	return t.ReservedAt.Before(t.AdmissionUntil) && !t.AdmissionUntil.After(purge.Add(-time.Minute)) &&
		t.ConsumeUntil.Equal(purge.Add(-30*time.Second)) && p.ValidUntil.Equal(t.ConsumeUntil) &&
		!purge.After(t.OriginalAcceptancePurgeAt) && purge.After(t.ReservedAt.Add(time.Minute)) &&
		t.RetainUntil.After(purge) && !t.RetainUntil.After(t.ReservedAt.Add(3660*24*time.Hour))
}

func (t ConnectorRetirementTicket) Clone() ConnectorRetirementTicket {
	if t.Policy.History != nil {
		copy := *t.Policy.History
		t.Policy.History = &copy
	}
	return t
}

// MatchesCohort is a pure exact comparison, never source or consumption
// authority. The exact accepted global backing and unchanged behavioral source
// are required. Every current effect separately checks the complete observed
// source; future peer-specific complete ConfigMap digests are not invented at
// global backing promotion.
func (t ConnectorRetirementTicket) MatchesCohort(binding fleet.PeerBinding, behavior identity.Revision, backing fleet.ConnectorBackingObservation) bool {
	return t.Valid() && t.Binding == binding && t.Behavior == behavior && t.BackingRevision == backing.Revision && t.BackingDigest == backing.Digest
}

// CanStart bounds one actual current SQL request without extending the
// immutable ticket. It does not select a retirement reason or prove admission.
func (t ConnectorRetirementTicket) CanStart(observedAt, until, now time.Time) bool {
	return t.Valid() && identity.Fresh(observedAt, until, now, 5*time.Second) && !observedAt.Before(t.ReservedAt) && !until.After(t.ConsumeUntil)
}

const ConnectorRetirementSetVersion = "connector-retirement-set/v1"

// ConnectorRetirementSet is an immutable commitment on the original accepting
// operation. It is never a substitute for recomputing the exact retained SQL
// set under the original admission/acknowledgement/promotion locks.
type ConnectorRetirementSet struct {
	Version string
	Count   int64
	Digest  artifact.Digest
}

func (s ConnectorRetirementSet) Valid() bool {
	return s.Version == ConnectorRetirementSetVersion && s.Count >= 1 && s.Count <= 4096 && s.Digest != (artifact.Digest{})
}
