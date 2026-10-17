package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityAuditProfilesFormat = "accepted-capacity-audit-profiles/v1"

// CapacityAuditProfile is one already backed root lane. Every normal-lane
// consumer selects this same policy; it is not duplicated per component.
type CapacityAuditProfile struct {
	Policy          OperationLifecyclePolicy
	RetainedSeconds int64
}

// AcceptedCapacityAuditProfiles is a bounded observation for selecting an
// auditor before a new Begin. It is neither an audit-intent replay result nor
// authority to create or resize a pool. Existing intents retain their original
// lifecycle binding even after this observation or its revision expires.
type AcceptedCapacityAuditProfiles struct {
	Format, RootID, InstallationID, QualificationID, AccountVersion string
	QualificationDigest, PlanDigest                                 artifact.Digest
	ConfigurationRevision, SourceRevision                           int64
	Normal, Resolution                                              CapacityAuditProfile
	ObservedAt, FreshUntil                                          time.Time
}

func (v AcceptedCapacityAuditProfiles) Valid(now time.Time) bool {
	if v.Format != CapacityAuditProfilesFormat || !authorization.UUID(v.RootID) || !authorization.UUID(v.InstallationID) || !authorization.UUID(v.QualificationID) || !identity.Text(v.AccountVersion, 64) || v.QualificationDigest == (artifact.Digest{}) || v.PlanDigest == (artifact.Digest{}) || v.ConfigurationRevision < 1 || v.ConfigurationRevision >= 1<<60 || v.SourceRevision < 1 || v.SourceRevision >= 1<<60 || !microTime(v.ObservedAt) || !microTime(v.FreshUntil) || !identity.Fresh(v.ObservedAt, v.FreshUntil, now, 5*time.Second) {
		return false
	}
	for _, lane := range []struct {
		name  string
		value CapacityAuditProfile
	}{{"normal", v.Normal}, {"resolution", v.Resolution}} {
		p := lane.value.Policy
		if !p.CertificateVerificationBacked() || p.History.Layout != OperationVerificationHistoryLayout || p.RootID != v.RootID || p.InstallationID != v.InstallationID || p.Lane != lane.name || p.BackingRevision != v.ConfigurationRevision || p.OverdueTerminal != OperationOverdueTerminal || v.FreshUntil.After(p.ValidUntil) || lane.value.RetainedSeconds < 60 || lane.value.RetainedSeconds > 316224000 || lane.value.RetainedSeconds <= 2*p.BackupHorizonSeconds+3*p.CleanupBudgetSeconds+p.ProofWindowSeconds+30 {
			return false
		}
	}
	return v.Normal.Policy.StoreID == v.Resolution.Policy.StoreID
}
