package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
)

// RetireStaging removes only the original staging policy's effect, preserving
// its UID/name/binding and every other field. Final workload protection is
// independently proven before and after. An uncertain original UPDATE admits
// exact lookup only. A positively completed exact API conflict permits one
// additional conditional UPDATE within the unchanged original interval.
func (s *InitialPreparer) RetireStaging(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	cm, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, e
	}
	if w.Activation.Handover == nil {
		return zero, cfg.ErrChanged
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	h := w.Activation.Handover
	if h.Staging != nil && h.Staging.Receipt != nil {
		return w, nil
	}
	path := "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + s.plan.Workload.StagingGuard
	raw, e := s.creator.raw(ctx, path, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	fresh := false
	var old admission.ValidatingAdmissionPolicy
	if h.Staging == nil {
		if strictGuardJSON(raw, &old) != nil || old.APIVersion != "admissionregistration.k8s.io/v1" || old.Kind != "ValidatingAdmissionPolicy" || old.Name != s.plan.Workload.StagingGuard || string(old.UID) != s.staging.PolicyUID || old.Generation != s.staging.PolicyGeneration || old.DeletionTimestamp != nil || len(old.OwnerReferences) != 0 || len(old.Finalizers) != 0 {
			return zero, cfg.ErrChanged
		}
		expected := s.creator.policy.Spec.DeepCopy()
		normalizePermissionPolicy(expected)
		normalizePermissionPolicy(&old.Spec)
		if !equalJSON(old.Spec, *expected) {
			return zero, cfg.ErrChanged
		}
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		started := s.protection.observer.now().UTC().Truncate(time.Microsecond)
		claimUntil := until.UTC().Truncate(time.Microsecond)
		if !initialHandoverInterval(started, claimUntil) {
			return zero, cfg.ErrUnavailable
		}
		h.Staging = &contracts.InitialPreparationStagingRetirement{ID: id, PolicyResourceVersion: old.ResourceVersion, StartedAt: started, Until: claimUntil}
		if e = s.handoverWrite(ctx, cm, w, until); e != nil {
			return zero, e
		}
		fresh = true
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		h = w.Activation.Handover
	}
	if !fresh {
		cm, w, e = s.persistHandoverConflict(ctx, cm, w, "staging", until)
		if e != nil {
			return zero, e
		}
		h = w.Activation.Handover
	}
	if fresh {
		effect, done := context.WithDeadline(ctx, h.Staging.Until)
		defer done()
		if e = initialHandoverDeadline(effect, s.protection.observer.now, h.Staging.Until); e != nil {
			return zero, e
		}
		retired, _, e := InitialRetiredStagingAdmission(s.plan)
		if e != nil {
			return zero, e
		}
		old.Spec = *retired.Spec.DeepCopy()
		raw, e = json.Marshal(old)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		var status int
		raw, status, e = s.conditionalHandoverPut(effect, path, raw)
		if e != nil {
			if !s.retainHandoverConflict(effect, w, "staging", raw, status) {
				return zero, cfg.ErrUnavailable
			}
			cm, w, e = s.persistHandoverConflict(effect, cm, w, "staging", until)
			if e != nil {
				return zero, e
			}
			h = w.Activation.Handover
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, h.Staging.Until); e != nil {
			return zero, e
		}
	}
	if h.Staging.FirstConflict != nil && h.Staging.Retry == nil {
		until = identity.Earlier(until, h.Staging.Until)
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
			return zero, e
		}
		effect, done := context.WithDeadline(ctx, until)
		defer done()
		raw, e = s.creator.raw(effect, path, nil)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		// A status-only update may change resourceVersion. Every identity,
		// metadata and original protected policy field must remain exact.
		if strictGuardJSON(raw, &old) != nil || old.APIVersion != "admissionregistration.k8s.io/v1" || old.Kind != "ValidatingAdmissionPolicy" || old.Name != s.plan.Workload.StagingGuard || string(old.UID) != s.staging.PolicyUID || old.Generation != s.staging.PolicyGeneration || old.DeletionTimestamp != nil || len(old.OwnerReferences) != 0 || len(old.Finalizers) != 0 || old.ResourceVersion == h.Staging.PolicyResourceVersion {
			return zero, cfg.ErrChanged
		}
		expected := s.creator.policy.Spec.DeepCopy()
		normalizePermissionPolicy(expected)
		normalizePermissionPolicy(&old.Spec)
		if !equalJSON(old.Spec, *expected) {
			return zero, cfg.ErrChanged
		}
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		h.Staging.Retry = &contracts.InitialPreparationConditionalRetry{ID: id, ResourceVersion: old.ResourceVersion, ClaimedAt: s.protection.observer.now().UTC().Truncate(time.Microsecond)}
		if e = s.handoverWrite(effect, cm, w, until); e != nil {
			return zero, e
		}
		cm, w, e = s.read(effect)
		if e != nil {
			return zero, e
		}
		h = w.Activation.Handover
		if h.Staging.Retry == nil || h.Staging.Retry.ID != id || h.Staging.Retry.ResourceVersion != old.ResourceVersion {
			return zero, cfg.ErrChanged
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, until); e != nil {
			return zero, e
		}
		retired, _, e := InitialRetiredStagingAdmission(s.plan)
		if e != nil {
			return zero, e
		}
		old.Spec = *retired.Spec.DeepCopy()
		raw, e = json.Marshal(old)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		raw, _, e = s.conditionalHandoverPut(effect, path, raw)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, until); e != nil {
			return zero, e
		}
	}
	policy, e := s.decodedStagingRetirement(raw)
	if e != nil {
		return zero, e
	}
	receipt := &contracts.InitialPreparationPolicyReceipt{UID: string(policy.UID), Generation: policy.Generation, ResourceVersion: policy.ResourceVersion}
	h.Staging.Receipt = receipt
	// This acknowledgement is public history, not a renewed retirement/launch
	// permit. Qualified current controller status is still required by the write.
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}
