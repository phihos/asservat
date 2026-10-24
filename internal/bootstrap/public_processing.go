package bootstrap

import (
	"context"
	"errors"
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
	// refused receives a fixed step name per refusal; diagnostics only.
	refused func(string)
}

func (s publicProcessingChanges) Change(ctx context.Context, current identities.CurrentIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	var zero value.ProcessingReceipt
	// ADR-210 decision 3: the release lane is not composed.
	if c.Action == "release_processing" {
		return zero, value.ErrUnavailable
	}
	accepted, err := s.profiles.ReadCapacityAuditProfiles(ctx)
	if err != nil {
		s.refuse("profiles")
		return zero, value.ErrUnavailable
	}
	receipt, err := privacy.ProcessingChanges{RootID: s.root, InstallationID: s.installation, Policies: s.policies, Recovery: s.recovery, Decisions: s.decisions,
		Audit: s.audit, MAC: s.mac, AuditPolicy: accepted.Normal.Policy, RetainedSeconds: accepted.Normal.RetainedSeconds, Now: time.Now}.Change(ctx, current, c)
	if err != nil {
		s.refuse(s.refusedStep(ctx, current))
	}
	return receipt, err
}

func (s publicProcessingChanges) refuse(step string) {
	if s.refused != nil {
		s.refused(step)
	}
}

// refusedStep repeats the authority reads after a refusal, for a fixed step
// name only: the change has already failed and nothing here is authority.
// Diagnostics retain the original request lifetime, keep their five-second
// ceiling, and stop between reads.
func (s publicProcessingChanges) refusedStep(ctx context.Context, current identities.CurrentIdentity) string {
	if s.refused == nil {
		return ""
	}
	if ctx == nil || ctx.Err() != nil {
		return "request"
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	i, err := current.ResolveIdentity(call)
	if call.Err() != nil {
		return "request"
	}
	if err != nil || !i.Valid(time.Now()) {
		return "identity"
	}
	p, err := s.policies.DownloadPolicy(call)
	if call.Err() != nil {
		return "request"
	}
	if err != nil {
		var step interface{ FixedStep() string }
		if errors.As(err, &step) {
			return "policy/" + step.FixedStep()
		}
		return "policy"
	}
	if p.RootID != s.root || p.InstallationID != s.installation || !p.Operator(i, time.Now()) {
		return "operator"
	}
	_, err = s.recovery.RecoveryState(call)
	if call.Err() != nil {
		return "request"
	}
	if err != nil {
		return "recovery"
	}
	return "change"
}
