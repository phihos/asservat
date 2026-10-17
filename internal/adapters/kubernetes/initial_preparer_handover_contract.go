package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	"time"
)

// This is the final guard/source/configuration inventory, distinct from the
// declarative nine/eleven-object RBAC inventory in preparerObjects.
const initialPreparationFinalInputCount = 9
const initialPreparationConfigurationIndex = 8

func (s *InitialPreparer) HandoverEnabled() bool {
	return s != nil && s.plan.Handover == contracts.InitialPreparationHandoverProtocol
}
func initialHandoverTime(t time.Time) bool {
	return t.Location() == time.UTC && t.Year() >= 2020 && t.Year() < 9999 && t.Equal(t.Truncate(time.Microsecond))
}
func initialHandoverInterval(start, end time.Time) bool {
	return initialHandoverTime(start) && initialHandoverTime(end) && start.Before(end) && end.Sub(start) <= 5*time.Second
}
func (s *InitialPreparer) validHandover(w contracts.InitialPreparationRoot) bool {
	if w.Activation == nil || w.Activation.Handover == nil {
		return true
	}
	a := w.Activation
	h := a.Handover
	if !s.HandoverEnabled() || a.Pod == nil || a.Pod.Receipt == nil || a.Credentials == nil || a.Inputs == nil || len(a.Inputs.Creates) != initialPreparationFinalInputCount || !authorization.UUID(h.OperationID) || h.StartupDigest != a.Credentials.StartupDigest || h.Input.Name != s.plan.Workload.Configuration || h.Credentials.Name != s.plan.Workload.Credentials || !authorization.UUID(h.Input.UID) || !authorization.UUID(h.Credentials.UID) || !initialHandoverTime(h.ReviewedAt) {
		return false
	}
	for _, r := range a.Pod.Requests {
		if r.Completion == nil {
			return false
		}
	}
	for _, r := range a.Inputs.Creates {
		if r.Receipt == nil {
			return false
		}
	}
	if a.Inputs.Creates[initialPreparationConfigurationIndex].Receipt.UID != h.Input.UID {
		return false
	}
	seen := map[string]bool{a.Pod.OperationID: true}
	for _, r := range w.Creates {
		seen[r.OperationID] = true
	}
	for _, r := range a.Inputs.Creates {
		seen[r.OperationID] = true
	}
	if seen[h.OperationID] {
		return false
	}
	seen[h.OperationID] = true
	if t := h.Staging; t != nil {
		if !authorization.UUID(t.ID) || seen[t.ID] || !identity.Text(t.PolicyResourceVersion, 128) || !initialHandoverInterval(t.StartedAt, t.Until) || t.StartedAt.Before(h.ReviewedAt) {
			return false
		}
		seen[t.ID] = true
		if !validHandoverRetry(t.FirstConflict, t.Retry, t.PolicyResourceVersion, t.StartedAt, t.Until, seen) || t.FirstConflict != nil && t.Receipt != nil && t.Retry == nil {
			return false
		}
		if r := t.Receipt; r != nil {
			if r.UID != s.staging.PolicyUID || r.Generation != s.staging.PolicyGeneration+1 || !identity.Text(r.ResourceVersion, 128) {
				return false
			}
		}
	}
	if l := h.Launch; l != nil {
		if h.Staging == nil || h.Staging.Receipt == nil || !authorization.UUID(l.ID) || seen[l.ID] || !identity.Text(l.PodResourceVersion, 128) || !initialHandoverInterval(l.StartedAt, l.Until) || l.StartedAt.Before(h.Staging.StartedAt) {
			return false
		}
		seen[l.ID] = true
		if !validHandoverRetry(l.FirstConflict, l.Retry, l.PodResourceVersion, l.StartedAt, l.Until, seen) || l.FirstConflict != nil && l.Observed && l.Retry == nil {
			return false
		}
	}
	if h.Cleanup != nil && seen[h.Cleanup.OperationID] {
		return false
	}
	if !s.validHandoverCleanup(w) {
		return false
	}
	return true
}

// The canonical retirement keeps the original policy and binding identities.
// Only this one false condition is added; it is not a selector/reduction engine.
func InitialRetiredStagingAdmission(p contracts.InitialPreparationPlan) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !validPreparerPlan(p) || p.Handover != contracts.InitialPreparationHandoverProtocol {
		return nil, nil, cfg.ErrInvalid
	}
	policy, binding, err := InitialNamespaceAdmission(preparerAdministration(p))
	if err != nil {
		return nil, nil, err
	}
	policy.Spec.MatchConditions = append(policy.Spec.MatchConditions, admission.MatchCondition{Name: "initial-handover-complete", Expression: "false"})
	return policy, binding, nil
}

func validHandoverRetry(conflict *contracts.InitialPreparationConflictCompletion, retry *contracts.InitialPreparationConditionalRetry, originalRV string, start, until time.Time, seen map[string]bool) bool {
	if conflict == nil {
		return retry == nil
	}
	if !initialHandoverTime(conflict.CompletedAt) || conflict.CompletedAt.Before(start) || !conflict.CompletedAt.Before(until) {
		return false
	}
	if retry == nil {
		return true
	}
	if !authorization.UUID(retry.ID) || seen[retry.ID] || !identity.Text(retry.ResourceVersion, 128) || retry.ResourceVersion == originalRV || !initialHandoverTime(retry.ClaimedAt) || retry.ClaimedAt.Before(conflict.CompletedAt) || !retry.ClaimedAt.Before(until) {
		return false
	}
	seen[retry.ID] = true
	return true
}
