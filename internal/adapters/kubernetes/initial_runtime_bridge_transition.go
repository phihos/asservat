package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *InitialRuntimeBridge) phasePolicy(ctx context.Context, state contracts.InitialRuntimeBridgeState) (*admission.ValidatingAdmissionPolicy, int, error) {
	raw, err := s.preparer.creator.raw(ctx, s.policyPath(), nil)
	if err != nil {
		return nil, 0, cfg.ErrUnavailable
	}
	if err = s.deadline(ctx); err != nil {
		return nil, 0, err
	}
	var p admission.ValidatingAdmissionPolicy
	if strictGuardJSON(raw, &p) != nil || p.APIVersion != "admissionregistration.k8s.io/v1" || p.Kind != "ValidatingAdmissionPolicy" || p.Name != s.initial.WorkloadGuard.Name || string(p.UID) != s.guards[0].pin.PolicyUID || p.DeletionTimestamp != nil || len(p.OwnerReferences) != 0 || len(p.Finalizers) != 0 || !identity.Text(p.ResourceVersion, 128) {
		return nil, 0, cfg.ErrChanged
	}
	phase := int(p.Generation - s.guards[0].pin.PolicyGeneration)
	if phase < 0 || phase > 2 {
		return nil, 0, cfg.ErrChanged
	}
	normalizePermissionPolicy(&p.Spec)
	if !equalJSON(p.Spec, s.policies[phase].Spec) {
		return nil, 0, cfg.ErrChanged
	}
	switch phase {
	case 0:
		if p.Annotations[initialRuntimeBridgeMarker] != "" || state.Probe != nil && state.Probe.Receipt != nil {
			return nil, 0, cfg.ErrChanged
		}
	case 1:
		if state.Probe == nil || p.Annotations[initialRuntimeBridgeMarker] != state.Probe.OperationID || state.Retained != nil && state.Retained.Receipt != nil {
			return nil, 0, cfg.ErrChanged
		}
	case 2:
		if state.Retained == nil || p.Annotations[initialRuntimeBridgeMarker] != state.Retained.OperationID {
			return nil, 0, cfg.ErrChanged
		}
	}
	return &p, phase, nil
}

// current retains every initial root/namespace/input identity. A pending
// candidate is recognized only with its exact pre-recorded claim and actual
// native canonical policy; the journal alone cannot choose a weaker guard.
func (s *InitialRuntimeBridge) current(ctx context.Context, state contracts.InitialRuntimeBridgeState) (*admission.ValidatingAdmissionPolicy, int, time.Time, error) {
	original, ok := ctx.Deadline()
	if !ok {
		return nil, 0, time.Time{}, cfg.ErrInvalid
	}
	p, phase, err := s.phasePolicy(ctx, state)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	_, w, c, until, err := s.preparer.currentHandoverWithFinal(ctx, s.guards[phase])
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if w.RootUID != s.rootUID || !equalJSON(c, s.initial) {
		return nil, 0, time.Time{}, cfg.ErrChanged
	}
	if err = initialHandoverDeadline(ctx, s.source.client.now, until); err != nil {
		return nil, 0, time.Time{}, err
	}
	until = identity.Earlier(until, original)
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if phase > 0 {
		// The intermediate policy permits only these dry-run probes. Actual
		// runtime operations remain denied until both independent guards pass.
		if e := s.currentProbeAccounts(ctx); e != nil {
			return nil, 0, time.Time{}, e
		}
		proof, e := s.source.ReadConfigurationRoleSource(ctx)
		if e != nil {
			return nil, 0, time.Time{}, e
		}
		if proof.IssuerEpoch != s.record.Scope.IssuerEpoch {
			return nil, 0, time.Time{}, cfg.ErrChanged
		}
		until = identity.Earlier(until, proof.FreshUntil)
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, until)
		defer stop()
		if e = initialHandoverDeadline(ctx, s.source.client.now, proof.FreshUntil); e != nil {
			return nil, 0, time.Time{}, e
		}
	} else {
		// Before the intermediate CAS the old namespace-wide guard masks runtime
		// probes. Only structural installation is checked; it grants no runtime
		// effect. The old guard remains the independently proven authority here.
		if _, err = s.source.configurationRoleGuardVersions(ctx); err != nil {
			return nil, 0, time.Time{}, err
		}
	}
	// Canonical re-read after all blocking proof work detects a concurrent
	// policy change without selecting a different phase or extending its end.
	last, lastPhase, err := s.phasePolicy(ctx, state)
	if err != nil || lastPhase != phase || last.Generation != p.Generation || !equalJSON(last.Spec, p.Spec) {
		return nil, 0, time.Time{}, cfg.ErrChanged
	}
	if err = s.deadline(ctx); err != nil {
		return nil, 0, time.Time{}, err
	}
	return last, phase, until, nil
}

func (s *InitialRuntimeBridge) readCurrent(ctx context.Context) (contracts.InitialRuntimeBridgeSnapshot, *core.Secret, *admission.ValidatingAdmissionPolicy, int, error) {
	var zero contracts.InitialRuntimeBridgeSnapshot
	// The untrusted journal cannot replace administrator/bootstrap checks. It
	// is parsed only after those checks and then validated under the exact final
	// guard selected from its two closed candidates.
	if err := s.preparer.creator.administrator(ctx); err != nil {
		return zero, nil, nil, 0, err
	}
	if _, _, err := s.preparer.protection.current(ctx); err != nil {
		return zero, nil, nil, 0, err
	}
	out, obj, err := s.read(ctx)
	if err != nil {
		return zero, nil, nil, 0, err
	}
	policy, phase, until, err := s.current(ctx, out.State)
	if err != nil {
		return zero, nil, nil, 0, err
	}
	out.ValidUntil = identity.Earlier(out.ValidUntil, until)
	return out, obj, policy, phase, nil
}

// Explicit accounts are independently read even when Kubernetes cached an old
// token authentication. A probe UID in the plan is not current identity proof.
func (s *InitialRuntimeBridge) currentProbeAccounts(ctx context.Context) error {
	check := func(client *PermissionClient, name, uid string) error {
		raw, err := client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
		var who auth.SelfSubjectReview
		if err != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.initial.Namespace.Name+":"+name || who.Status.UserInfo.UID != uid {
			return cfg.ErrUnavailable
		}
		raw, err = s.source.client.raw(ctx, "/api/v1/namespaces/"+s.initial.Namespace.Name+"/serviceaccounts/"+name, nil)
		var account core.ServiceAccount
		if err != nil || strictGuardJSON(raw, &account) != nil || account.APIVersion != "v1" || account.Kind != "ServiceAccount" || !ownerMetadata(account.ObjectMeta, s.initial.Namespace.Name, name, uid) {
			return cfg.ErrChanged
		}
		return s.deadline(ctx)
	}
	p := s.administration.OwnerProbe
	if err := check(s.source.protection.probe, p.ServiceAccount, p.ServiceAccountUID); err != nil {
		return err
	}
	for _, p := range s.administration.SourceProbes {
		probe := s.source.owner.protection.probe
		if p.ConfigMap == s.source.input.FleetSource.Name {
			probe = s.source.fleet.protection.probe
		}
		if err := check(probe, p.ServiceAccount, p.ServiceAccountUID); err != nil {
			return err
		}
	}
	return nil
}
