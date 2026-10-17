package kubernetes

import (
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
)

func initialPreparationDigest(v string) (artifact.Digest, error) {
	var out artifact.Digest
	raw, e := hex.DecodeString(v)
	if e != nil || len(raw) != len(out) || hex.EncodeToString(raw) != v {
		return out, cfg.ErrChanged
	}
	copy(out[:], raw)
	return out, nil
}

// stagingHandover checks either the unchanged original guard, or the one
// recorded canonical inert transition. It never chooses or adopts another UID,
// policy shape, binding, generation or administrator set.
func (s *InitialPreparer) stagingHandover(ctx context.Context, w contracts.InitialPreparationRoot) error {
	expected := s.creator.policy.DeepCopy()
	normalizePermissionPolicy(&expected.Spec)
	pin := s.staging
	var stage *contracts.InitialPreparationStagingRetirement
	if w.Activation != nil && w.Activation.Handover != nil {
		stage = w.Activation.Handover.Staging
	}
	if stage == nil {
		_, e := checkAdmissionGuard(ctx, s.creator, s.plan.Workload.StagingGuard, pin, expected.Spec, s.creator.binding.Spec)
		return e
	}
	// The pre-transition shape remains readable after a claim, but cannot grant
	// a second UPDATE. Only the live claim owner may issue the original request.
	if stage.Receipt == nil {
		if _, e := checkAdmissionGuard(ctx, s.creator, s.plan.Workload.StagingGuard, pin, expected.Spec, s.creator.binding.Spec); e == nil {
			return nil
		}
	}
	retired, _, e := InitialRetiredStagingAdmission(s.plan)
	if e != nil {
		return e
	}
	normalizePermissionPolicy(&retired.Spec)
	pin.PolicyGeneration++
	if stage.Receipt != nil && (stage.Receipt.UID != pin.PolicyUID || stage.Receipt.Generation != pin.PolicyGeneration) {
		return cfg.ErrChanged
	}
	_, e = checkAdmissionGuard(ctx, s.creator, s.plan.Workload.StagingGuard, pin, retired.Spec, s.creator.binding.Spec)
	if e != nil {
		// A controller has not yet qualified the exact new generation. This is
		// unavailable, never a current guard; only that exact pending shape is
		// eligible for bounded observation by the supervisor.
		raw, readErr := s.creator.raw(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+s.plan.Workload.StagingGuard, nil)
		if readErr == nil {
			if policy, decodeErr := s.decodedStagingRetirement(raw); decodeErr == nil && policy.Status.ObservedGeneration < policy.Generation {
				return cfg.ErrUnavailable
			}
		}
	}
	return e
}

// currentHandover is deliberately independent of original token/provider
// lifetimes: it permits only current administrator review of the same protected
// public attempt. Every effect separately checks its original launch/material
// interval. A historical successful attempt never activates a recovered DB.
func (s *InitialPreparer) currentHandover(ctx context.Context) (*core.ConfigMap, contracts.InitialPreparationRoot, contracts.InitialInstaller, time.Time, error) {
	return s.currentHandoverWithFinal(ctx, nil)
}

// Only the concrete runtime bridge supplies an alternate final protection. Its
// policy is one of the two compiled candidates; every original root/input and
// bootstrap check below remains mandatory. Ordinary history keeps the nil path.
func (s *InitialPreparer) currentHandoverWithFinal(ctx context.Context, alternate *configMapProtection) (*core.ConfigMap, contracts.InitialPreparationRoot, contracts.InitialInstaller, time.Time, error) {
	var zero contracts.InitialPreparationRoot
	var none contracts.InitialInstaller
	if !s.HandoverEnabled() || ctx == nil {
		return nil, zero, none, time.Time{}, cfg.ErrInvalid
	}
	start := s.protection.observer.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if e := s.creator.administrator(ctx); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	_, bound, e := s.protection.current(ctx)
	until = identity.Earlier(until, bound)
	if e != nil {
		return nil, zero, none, time.Time{}, e
	}
	cm, w, e := s.read(ctx)
	if e != nil {
		return nil, zero, none, time.Time{}, e
	}
	if w.RootUID == "" || w.Phase == "declaring" || w.Activation == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil || w.Activation.Credentials == nil || w.Activation.Inputs == nil || len(w.Activation.Inputs.Creates) != initialPreparationFinalInputCount {
		return nil, zero, none, time.Time{}, cfg.ErrChanged
	}
	for _, entry := range w.Activation.Inputs.Creates {
		if entry.Receipt == nil {
			return nil, zero, none, time.Time{}, cfg.ErrUnavailable
		}
	}
	c, e := s.inputConfiguration(w)
	if e != nil || preparationDigest(c) != w.Activation.Credentials.StartupDigest {
		return nil, zero, none, time.Time{}, cfg.ErrChanged
	}
	if e = s.stagingHandover(ctx, w); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	if e = s.checkHistoryProbe(ctx); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	// The target configuration is independently read and compared against the
	// full original value; no mutable witness contents are treated as authority.
	entry := w.Activation.Inputs.Creates[initialPreparationConfigurationIndex]
	object, e := s.publicInputResource(w, initialPreparationConfigurationIndex)
	if e != nil || entry.SpecDigest != object.digest {
		return nil, zero, none, time.Time{}, cfg.ErrChanged
	}
	raw, e := s.creator.raw(ctx, object.path+"/"+entry.Name, nil)
	if e != nil {
		return nil, zero, none, time.Time{}, cfg.ErrUnavailable
	}
	if _, e = s.verifyPublicInput(raw, object, entry); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	final, e := s.finalHandoverProtection(c)
	if e != nil {
		return nil, zero, none, time.Time{}, e
	}
	if alternate != nil {
		// A different namespace, source, administrator set or guard identity is
		// never an alternate interpretation of this original handover.
		if alternate.plan.Name != final.plan.Name || alternate.plan.SourceName != final.plan.SourceName || alternate.plan.ControlNamespace != final.plan.ControlNamespace || !equalJSON(alternate.plan.Administrators, final.plan.Administrators) || alternate.pin.PolicyUID != final.pin.PolicyUID || alternate.pin.BindingUID != final.pin.BindingUID || alternate.pin.BindingResourceVersion != final.pin.BindingResourceVersion || alternate.pin.PolicyGeneration < final.pin.PolicyGeneration || alternate.pin.PolicyGeneration > final.pin.PolicyGeneration+2 {
			return nil, zero, none, time.Time{}, cfg.ErrChanged
		}
		final = alternate
	}
	_, bound, e = final.current(ctx)
	until = identity.Earlier(until, bound)
	if e != nil {
		return nil, zero, none, time.Time{}, e
	}
	if e = s.stagingHandover(ctx, w); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return nil, zero, none, time.Time{}, e
	}
	return cm, w, c, until, nil
}

// Kept separate from checkAdmissionGuard because a staging UPDATE receipt may
// precede the API controller's observedGeneration. Such a receipt is provenance
// only; currentHandover still requires the normal qualified controller status.
func (s *InitialPreparer) decodedStagingRetirement(raw []byte) (*admission.ValidatingAdmissionPolicy, error) {
	var policy admission.ValidatingAdmissionPolicy
	if strictGuardJSON(raw, &policy) != nil || policy.APIVersion != "admissionregistration.k8s.io/v1" || policy.Kind != "ValidatingAdmissionPolicy" || policy.Name != s.plan.Workload.StagingGuard || string(policy.UID) != s.staging.PolicyUID || policy.Generation != s.staging.PolicyGeneration+1 || policy.DeletionTimestamp != nil || len(policy.OwnerReferences) != 0 || len(policy.Finalizers) != 0 || !identity.Text(policy.ResourceVersion, 128) {
		return nil, cfg.ErrChanged
	}
	want, _, e := InitialRetiredStagingAdmission(s.plan)
	if e != nil {
		return nil, e
	}
	normalizePermissionPolicy(&policy.Spec)
	normalizePermissionPolicy(&want.Spec)
	if !equalJSON(policy.Spec, want.Spec) {
		return nil, cfg.ErrChanged
	}
	return &policy, nil
}
