package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const initialPreparationRetiredAnnotation = "asservat.io/initial-preparation-retired"

var initialPreparationCleanupSteps = [...]string{"sql", "wrap", "unwrap", "probe", "target-secrets", "setup-rbac", "private-state", "pod"}

func (s *InitialPreparer) validHandoverCleanup(w contracts.InitialPreparationRoot) bool {
	if w.Activation == nil || w.Activation.Handover == nil {
		return false
	}
	h := w.Activation.Handover
	c := h.Cleanup
	if c == nil {
		return true
	}
	if h.Staging == nil || h.Staging.Receipt == nil || h.Launch == nil || !h.Launch.Observed || !authorization.UUID(c.OperationID) || !authorization.UUID(c.ActivatedClaimID) || c.OperationID == h.OperationID || c.OperationID == h.Launch.ID || c.OperationID == h.Staging.ID || !initialHandoverTime(c.StartedAt) || c.StartedAt.Before(h.Launch.StartedAt) || !identity.Text(c.PodResourceVersion, 128) || c.SQLState.Name != s.plan.Workload.Credentials+"-sql" || !authorization.UUID(c.SQLState.UID) || c.ProbeAnchor.Name != s.probeAnchorName() || !authorization.UUID(c.ProbeAnchor.UID) || c.Steps == nil || len(c.Steps) > len(initialPreparationCleanupSteps) {
		return false
	}
	for _, r := range w.Creates {
		if r.OperationID == c.OperationID {
			return false
		}
	}
	if w.Activation.Pod != nil && w.Activation.Pod.OperationID == c.OperationID {
		return false
	}
	if w.Activation.Inputs != nil {
		for _, r := range w.Activation.Inputs.Creates {
			if r.OperationID == c.OperationID {
				return false
			}
		}
	}
	previous := c.StartedAt
	for i, r := range c.Steps {
		if r.Step != initialPreparationCleanupSteps[i] || !initialHandoverTime(r.CompletedAt) || r.CompletedAt.Before(previous) {
			return false
		}
		previous = r.CompletedAt
	}
	return true
}
