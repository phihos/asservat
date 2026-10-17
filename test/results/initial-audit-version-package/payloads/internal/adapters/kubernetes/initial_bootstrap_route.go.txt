package kubernetes

import (
	"context"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

// OpenInitialBootstrap selects the installer-owned persisted capability. A new
// format is selected only after exact absence of every fixed owned name. An
// existing seed is inspected using PartialObjectMetadata only; a complete
// pre-seed prelude is recovered read-only under its original native guard.
// Partial/unprotected preludes are unavailable, never adopted or upgraded.
func OpenInitialBootstrap(ctx context.Context, config *rest.Config, desired contracts.InitialBootstrap) (_ *InitialBootstrap, err error) {
	if desired.Format != contracts.InitialBootstrapFormat && !contracts.InitialBootstrapHasPassiveHistory(desired.Format) {
		return nil, cfg.ErrInvalid
	}
	desired.Format = contracts.InitialBootstrapVersionedAuditFormat
	s, err := NewInitialBootstrap(ctx, config, desired)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			s.Close()
		}
	}()
	bounded, end, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if err = s.administrator(bounded); err != nil {
		return nil, err
	}
	ns, err := s.namespace(bounded)
	if err != nil {
		return nil, err
	}
	n := bootstrapNames(desired)
	raw, err := s.api.Get().AbsPath("/api/v1/namespaces/"+ns.Name+"/secrets/"+n.seed).SetHeader("Accept", bootstrapPartialMetadataAccept).MaxRetries(0).DoRaw(bounded)
	defer clear(raw)
	if err == nil {
		var m meta.PartialObjectMetadata
		if permissionJSON(raw, 16<<10, 4096) != nil || strictGuardJSON(raw, &m) != nil || m.APIVersion != "meta.k8s.io/v1" || m.Kind != "PartialObjectMetadata" || m.Name != n.seed || m.Namespace != ns.Name || !authorization.UUID(string(m.UID)) || !identity.Text(m.ResourceVersion, 128) || m.DeletionTimestamp != nil {
			return nil, cfg.ErrChanged
		}
		d, ok := bootstrapKnownDesired(desired, m.Annotations[initialBootstrapAnnotation])
		if !ok {
			return nil, cfg.ErrChanged
		}
		s.desired, s.seedUID = d, string(m.UID)
	} else if apierrors.IsNotFound(err) {
		// No effect root or private copy can precede the original seed. Neither an
		// unknown GET nor a missing seed in an existing installation is fresh.
		if err = s.bootstrapEffectsAbsent(bounded); err != nil {
			return nil, err
		}
		policyRaw, policyErr := s.get(bounded, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+n.guard)
		if policyErr == nil {
			var p admission.ValidatingAdmissionPolicy
			if strictGuardJSON(policyRaw, &p) != nil {
				return nil, cfg.ErrChanged
			}
			d, ok := bootstrapKnownDesired(desired, p.Annotations[initialBootstrapAnnotation])
			if !ok {
				return nil, cfg.ErrChanged
			}
			s.desired = d
			prelude, err := s.readOriginalPrelude(bounded, ns, &p)
			if err != nil {
				return nil, err
			}
			// No installation cluster exists yet. This private continuity probe
			// carries no invented cluster identity or exported authority digest.
			if err = s.qualifyPrelude(bounded, prelude); err != nil {
				return nil, err
			}
			if err = s.bootstrapEffectsAbsent(bounded); err != nil {
				return nil, err
			}
			s.routedPrelude = &prelude
		} else if apierrors.IsNotFound(policyErr) {
			if err = s.bootstrapPreludeAbsent(bounded); err != nil {
				return nil, err
			}
		} else {
			return nil, cfg.ErrUnavailable
		}
	} else {
		return nil, cfg.ErrUnavailable
	}
	current, err := s.namespace(bounded)
	if err != nil || current != ns || bounded.Err() != nil {
		return nil, cfg.ErrChanged
	}
	if err = s.administrator(bounded); err != nil || bounded.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	complete = true
	return s, nil
}

func bootstrapKnownDesired(input contracts.InitialBootstrap, digest string) (contracts.InitialBootstrap, bool) {
	for _, format := range []string{contracts.InitialBootstrapPassiveFormat, contracts.InitialBootstrapCopyClosureFormat, contracts.InitialBootstrapVersionedAuditFormat} {
		next := input
		next.Format = format
		if bootstrapDigest(next) == digest {
			return next, true
		}
	}
	return contracts.InitialBootstrap{}, false
}

func (s *InitialBootstrap) absent(ctx context.Context, paths []string) error {
	for _, path := range paths {
		var err error
		if strings.Contains(path, "/secrets/") {
			raw, e := s.api.Get().AbsPath(path).SetHeader("Accept", bootstrapPartialMetadataAccept).MaxRetries(0).DoRaw(ctx)
			clear(raw)
			err = e
		} else {
			_, err = s.get(ctx, path)
		}
		if !apierrors.IsNotFound(err) {
			return cfg.ErrChanged
		}
	}
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *InitialBootstrap) bootstrapEffectsAbsent(ctx context.Context) error {
	n := bootstrapNames(s.desired)
	base := "/api/v1/namespaces/" + s.desired.BootstrapNamespace
	paths := []string{"/api/v1/namespaces/" + s.desired.TargetNamespace, base + "/configmaps/" + n.root, base + "/configmaps/" + n.projection}
	for _, name := range []string{n.private, n.sqlMaterial, n.providerMaterial, n.passiveHistory} {
		paths = append(paths, base+"/secrets/"+name)
	}
	for _, name := range []string{n.continuity, n.copyGuard, s.desired.TargetNamespace + "-" + s.desired.Name + "-staging", s.desired.TargetNamespace + "-" + s.desired.Name + "-witness", s.desired.TargetNamespace + "-" + s.desired.Name + "-fleet", s.desired.TargetNamespace + "-" + s.desired.Name + "-workload"} {
		paths = append(paths, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+name, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/"+name)
	}
	return s.absent(ctx, paths)
}
func (s *InitialBootstrap) bootstrapPreludeAbsent(ctx context.Context) error {
	n := bootstrapNames(s.desired)
	base := "/api/v1/namespaces/" + s.desired.BootstrapNamespace
	rbac := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + s.desired.BootstrapNamespace
	return s.absent(ctx, []string{base + "/serviceaccounts/" + n.account, base + "/configmaps/" + n.marker, base + "/configmaps/" + n.continuityMarker, base + "/configmaps/" + n.copyMarker, base + "/secrets/" + n.anchor, rbac + "/roles/" + n.account, rbac + "/rolebindings/" + n.account, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + n.guard})
}
func (s *InitialBootstrap) readOriginalPrelude(ctx context.Context, ns contracts.WorkerObjectReference, policy *admission.ValidatingAdmissionPolicy) (contracts.InitialBootstrapPrelude, error) {
	p := contracts.InitialBootstrapPrelude{Namespace: ns}
	n := bootstrapNames(s.desired)
	wantPolicy, wantBinding, err := InitialBootstrapAdmission(s.desired)
	if err != nil || !bootstrapObjectMatches(wantPolicy, policy) || policy.Generation < 1 || policy.Status.ObservedGeneration != policy.Generation || policy.Status.TypeChecking == nil || len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
		return p, cfg.ErrChanged
	}
	base := "/api/v1/namespaces/" + ns.Name
	rbac := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns.Name
	objects := []struct {
		path string
		want runtime.Object
		ref  *contracts.WorkerObjectReference
	}{
		{base + "/serviceaccounts/" + n.account, bootstrapProbeAccount(s.desired), &p.Account},
		{rbac + "/roles/" + n.account, bootstrapProbeRole(s.desired), &p.Role},
		{rbac + "/rolebindings/" + n.account, bootstrapProbeBinding(s.desired), &p.Binding},
		{base + "/configmaps/" + n.marker, bootstrapProbeMarker(s.desired, n.marker), &p.Marker},
		{base + "/configmaps/" + n.continuityMarker, bootstrapProbeMarker(s.desired, n.continuityMarker), &p.ContinuityMarker},
		// This public immutable anchor has no private data; full exact shape is
		// checked before obtaining its observation-only bound token.
		{base + "/secrets/" + n.anchor, bootstrapProbeAnchor(s.desired), &p.TokenAnchor},
	}
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		p.CopyMarker = &contracts.WorkerObjectReference{}
		objects = append(objects, struct {
			path string
			want runtime.Object
			ref  *contracts.WorkerObjectReference
		}{base + "/configmaps/" + n.copyMarker, bootstrapProbeMarker(s.desired, n.copyMarker), p.CopyMarker})
	}
	for _, o := range objects {
		raw, e := s.get(ctx, o.path)
		got := bootstrapEmptyObject(o.want)
		if e != nil || strictGuardJSON(raw, got) != nil || !bootstrapObjectMatches(o.want, got) {
			return p, cfg.ErrChanged
		}
		*o.ref = bootstrapRef(got)
	}
	raw, err := s.get(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/"+n.guard)
	var binding admission.ValidatingAdmissionPolicyBinding
	if err != nil || strictGuardJSON(raw, &binding) != nil || !bootstrapObjectMatches(wantBinding, &binding) {
		return p, cfg.ErrChanged
	}
	p.Guard = contracts.OwnerDeploymentGuard{Name: n.guard, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.desired.Administrators...)}
	if !bootstrapPreludeValid(s.desired, p) || ctx.Err() != nil {
		return p, cfg.ErrChanged
	}
	return p, nil
}
