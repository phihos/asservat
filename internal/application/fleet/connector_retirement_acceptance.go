package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// BindConnectorRetirementAcceptance binds the proposed exact set into its
// original accepting intent. It is deterministic and has no effects. SQL must
// construct/check the complete eligible peer set under its root lock before
// committing this intent, and repeat its digest check before acknowledgement
// and promotion. An omitted peer cannot be detected by this pure helper.
func BindConnectorRetirementAcceptance(in audit.OperationIntent, policy audit.OperationLifecyclePolicy, tickets []audit.ConnectorRetirementTicket) (audit.OperationIntent, error) {
	var zero audit.OperationIntent
	if in.Name != "connector_process_enrollment" && in.Name != "connector_backing_acceptance" || in.Process == nil || !in.Process.Valid() || !policy.CertificateVerificationBacked() || policy.History.Layout != audit.ConnectorRetirementHistoryLayout {
		return zero, value.ErrUnavailable
	}
	digest, e := ConnectorRetirementSetDigest(tickets)
	if e != nil {
		return zero, e
	}
	set := audit.ConnectorRetirementSet{Version: audit.ConnectorRetirementSetVersion, Count: int64(len(tickets)), Digest: digest}
	if in.ConnectorReservations != nil && *in.ConnectorReservations != set {
		return zero, value.ErrUnavailable
	}
	copyActor := *in.Process
	in.Process = &copyActor
	in.ConnectorReservations = &set
	bound, e := auditapp.BindOperationLifecycle(in, policy)
	if e != nil || !bound.Valid() {
		return zero, value.ErrUnavailable
	}
	for _, t := range tickets {
		if t.AcceptanceID != bound.ID || t.RootID != bound.RootID || t.OriginalActor != *bound.Process || !t.ReservedAt.Equal(bound.CreatedAt) || !t.RetainUntil.Equal(bound.RetainUntil) || !t.OriginalAcceptancePurgeAt.Equal(bound.Lifecycle.OriginalPurgeAt) || !audit.CompatibleConnectorPolicy(t.Policy, policy) || in.Name == "connector_process_enrollment" && (len(tickets) != 1 || t.Binding != in.Process.Process.Binding || t.PrincipalDigest != in.PrincipalDigest || t.ServingSlots != in.Process.Deployment.ServingSlots || t.RetainedProcesses != in.Process.Deployment.RetainedProcesses || t.BackingRevision != policy.BackingRevision) || in.Name == "connector_backing_acceptance" && t.BackingRevision != policy.BackingRevision+1 {
			return zero, value.ErrUnavailable
		}
	}
	return bound, nil
}
