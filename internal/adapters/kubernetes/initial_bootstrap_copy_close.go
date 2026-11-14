package kubernetes

import (
	"context"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

func (s *InitialBootstrap) copyCurrent(ctx context.Context, p *InitialBootstrapPassiveRead, state *InitialBootstrapCopyState) error {
	if state == nil || state.Policy == nil || state.Binding == nil || p.Bundle.Observation.Prelude.CopyMarker == nil {
		return cfg.ErrInvalid
	}
	if err := s.current(ctx); err != nil {
		return err
	}
	policy, binding, err := InitialBootstrapCopyAdmission(s.desired, state.Claim)
	if err != nil {
		return err
	}
	plan := cfg.ConfigMapAdministration{Name: policy.Name, SourceName: p.Bundle.Observation.Prelude.CopyMarker.Name, ControlNamespace: cfg.NamespaceRef{Name: state.Claim.Namespace.Name, UID: state.Claim.Namespace.UID}}
	for _, a := range s.desired.Administrators {
		plan.Administrators = append(plan.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	pin := GuardPin{PolicyUID: state.Policy.UID, PolicyGeneration: 1, BindingUID: state.Binding.UID, BindingResourceVersion: state.Binding.ResourceVersion}
	proof, err := newConfigMapProtection(s.proof.observer, s.proof.probe, plan, pin, "initial-bootstrap-copy-tombstone", bootstrapCopyDenial)
	if err != nil {
		return err
	}
	normalizePermissionPolicy(&policy.Spec)
	proof.policy, proof.binding = policy.Spec, binding.Spec
	_, until, err := proof.current(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}
