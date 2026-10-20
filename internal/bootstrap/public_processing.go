package bootstrap

import (
	"context"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/privacy"
)

// publicProcessingChanges composes the ADR-210 privacy-operator change. The
// normal lane's policy and retained seconds are read from the current accepted
// capacity profile for each call, like the selected auditor that begins the
// audit: a renewal between the two fails closed and the change is retried.
type publicProcessingChanges struct {
	root, installation string
	profiles           auditapp.CapacityAuditProfiles
	policies           privacy.ProcessingPolicyReader
	recovery           privacy.ProcessingRecoveryReader
	decisions          privacy.ProcessingDecisions
	audit              privacy.ProcessingAudit
	mac                *auditapp.OperationMAC
}

func (s publicProcessingChanges) Change(ctx context.Context, current identities.CurrentIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	var zero value.ProcessingReceipt
	// ADR-210 decision 3: the release lane is not composed.
	if c.Action == "release_processing" {
		return zero, value.ErrUnavailable
	}
	accepted, err := s.profiles.ReadCapacityAuditProfiles(ctx)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	return privacy.ProcessingChanges{RootID: s.root, InstallationID: s.installation, Policies: s.policies, Recovery: s.recovery, Decisions: s.decisions,
		Audit: s.audit, MAC: s.mac, AuditPolicy: accepted.Normal.Policy, RetainedSeconds: accepted.Normal.RetainedSeconds, Now: time.Now}.Change(ctx, current, c)
}
