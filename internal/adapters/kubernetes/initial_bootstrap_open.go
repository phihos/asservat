package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// ErrInitialBootstrapMaterialRequired is returned only for a positively absent
// original seed after current administrator and namespace checks. It is not a
// generic retry classification and never means a lost existing seed is safe.
var ErrInitialBootstrapMaterialRequired = errors.New("initial bootstrap needs explicit private material")

func bootstrapRef(v runtime.Object) contracts.WorkerObjectReference {
	m := bootstrapObjectMetadata(v)
	return contracts.WorkerObjectReference{Name: m.Name, UID: string(m.UID)}
}

func (s *InitialBootstrap) publicPrelude(ctx context.Context) (contracts.InitialBootstrapPrelude, error) {
	var p contracts.InitialBootstrapPrelude
	if e := s.administrator(ctx); e != nil {
		return p, e
	}
	ns, e := s.namespace(ctx)
	if e != nil {
		return p, e
	}
	p.Namespace = ns
	n := bootstrapNames(s.desired)
	objects := []struct {
		path   string
		object runtime.Object
		ref    *contracts.WorkerObjectReference
	}{
		{"/api/v1/namespaces/" + ns.Name + "/serviceaccounts", bootstrapProbeAccount(s.desired), &p.Account},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns.Name + "/roles", bootstrapProbeRole(s.desired), &p.Role},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns.Name + "/rolebindings", bootstrapProbeBinding(s.desired), &p.Binding},
		{"/api/v1/namespaces/" + ns.Name + "/configmaps", bootstrapProbeMarker(s.desired, n.marker), &p.Marker},
		{"/api/v1/namespaces/" + ns.Name + "/configmaps", bootstrapProbeMarker(s.desired, n.continuityMarker), &p.ContinuityMarker},
		{"/api/v1/namespaces/" + ns.Name + "/secrets", bootstrapProbeAnchor(s.desired), &p.TokenAnchor},
	}
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		p.CopyMarker = &contracts.WorkerObjectReference{}
		objects = append(objects, struct {
			path   string
			object runtime.Object
			ref    *contracts.WorkerObjectReference
		}{
			"/api/v1/namespaces/" + ns.Name + "/configmaps", bootstrapProbeMarker(s.desired, n.copyMarker), p.CopyMarker,
		})
	}
	for _, o := range objects {
		got, e := s.ensureObject(ctx, o.path, o.object)
		if e != nil {
			return p, e
		}
		*o.ref = bootstrapRef(got)
	}
	policy, binding, e := InitialBootstrapAdmission(s.desired)
	if e != nil {
		return p, e
	}
	po, e := s.ensureObject(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", policy)
	if e != nil {
		return p, e
	}
	bo, e := s.ensureObject(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings", binding)
	if e != nil {
		return p, e
	}
	pp := po.(*admission.ValidatingAdmissionPolicy)
	bb := bo.(*admission.ValidatingAdmissionPolicyBinding)
	p.Guard = contracts.OwnerDeploymentGuard{Name: n.guard, PolicyUID: string(pp.UID), PolicyGeneration: pp.Generation, BindingUID: string(bb.UID), BindingResourceVersion: bb.ResourceVersion, Administrators: append([]contracts.OwnerDeploymentActor(nil), s.desired.Administrators...)}
	if pp.Generation < 1 || pp.Status.ObservedGeneration != pp.Generation || pp.Status.TypeChecking == nil {
		return p, ErrInitialPreparationPolicyPending
	}
	if len(pp.Status.TypeChecking.ExpressionWarnings) != 0 {
		return p, cfg.ErrChanged
	}
	now, e := s.namespace(ctx)
	if e != nil || now != p.Namespace || ctx.Err() != nil {
		return p, cfg.ErrChanged
	}
	return p, nil
}

func (s *InitialBootstrap) checkPrelude(ctx context.Context, p contracts.InitialBootstrapPrelude) error {
	if !bootstrapPreludeValid(s.desired, p) {
		return cfg.ErrInvalid
	}
	ns, e := s.namespace(ctx)
	if e != nil || ns != p.Namespace {
		return cfg.ErrChanged
	}
	n := bootstrapNames(s.desired)
	objects := []struct {
		path string
		want runtime.Object
		ref  contracts.WorkerObjectReference
	}{
		{"/api/v1/namespaces/" + ns.Name + "/serviceaccounts/" + n.account, bootstrapProbeAccount(s.desired), p.Account},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns.Name + "/roles/" + n.account, bootstrapProbeRole(s.desired), p.Role},
		{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns.Name + "/rolebindings/" + n.account, bootstrapProbeBinding(s.desired), p.Binding},
		{"/api/v1/namespaces/" + ns.Name + "/configmaps/" + n.marker, bootstrapProbeMarker(s.desired, n.marker), p.Marker},
		{"/api/v1/namespaces/" + ns.Name + "/configmaps/" + n.continuityMarker, bootstrapProbeMarker(s.desired, n.continuityMarker), p.ContinuityMarker},
		{"/api/v1/namespaces/" + ns.Name + "/secrets/" + n.anchor, bootstrapProbeAnchor(s.desired), p.TokenAnchor},
	}
	if contracts.InitialBootstrapHasCopyClosure(s.desired.Format) {
		objects = append(objects, struct {
			path string
			want runtime.Object
			ref  contracts.WorkerObjectReference
		}{
			"/api/v1/namespaces/" + ns.Name + "/configmaps/" + n.copyMarker, bootstrapProbeMarker(s.desired, n.copyMarker), *p.CopyMarker,
		})
	}
	for _, o := range objects {
		raw, e := s.get(ctx, o.path)
		got := bootstrapEmptyObject(o.want)
		if e != nil || strictGuardJSON(raw, got) != nil || !bootstrapObjectMatches(o.want, got) || bootstrapRef(got) != o.ref {
			return cfg.ErrChanged
		}
	}
	return nil
}

func (s *InitialBootstrap) qualify(ctx context.Context, p contracts.InitialBootstrapPrelude, cluster string) error {
	return s.qualifyWithClients(ctx, p, cluster)
}

// qualifyPrelude checks only public native continuity before any installation
// identity exists; no cluster assertion is manufactured for the private probe.
func (s *InitialBootstrap) qualifyPrelude(ctx context.Context, p contracts.InitialBootstrapPrelude) error {
	return s.qualifyWithClients(ctx, p, "")
}
func (s *InitialBootstrap) qualifyWithClients(ctx context.Context, p contracts.InitialBootstrapPrelude, cluster string) error {
	if e := s.checkPrelude(ctx, p); e != nil {
		return e
	}
	if e := s.administrator(ctx); e != nil {
		return e
	}
	if s.probeToken == "" || !time.Now().Before(s.probeUntil) {
		started := time.Now()
		request := auth.TokenRequest{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest"}, Spec: auth.TokenRequestSpec{Audiences: []string{s.desired.ProbeAudience}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: p.TokenAnchor.Name, UID: types.UID(p.TokenAnchor.UID)}}}
		raw, e := s.api.Post().AbsPath("/api/v1/namespaces/" + p.Namespace.Name + "/serviceaccounts/" + p.Account.Name + "/token").Body(&request).MaxRetries(0).DoRaw(ctx)
		defer clear(raw)
		var reply auth.TokenRequest
		// The API grants the requested 600 seconds at its processing instant;
		// the bounded request may consume at most five seconds before that.
		if e != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &reply) != nil || !identity.Text(reply.Status.Token, 16<<10) || !time.Now().Before(reply.Status.ExpirationTimestamp.Time) || reply.Status.ExpirationTimestamp.Time.After(started.Add(605*time.Second)) || ctx.Err() != nil {
			return cfg.ErrUnavailable
		}
		s.probeToken, s.probeUntil = reply.Status.Token, reply.Status.ExpirationTimestamp.Time
	}
	control := cfg.NamespaceRef{Name: p.Namespace.Name, UID: p.Namespace.UID}
	observer, e := bootstrapProofClient(s.config, cluster, control)
	if e != nil {
		return e
	}
	// Construct the probe transport without any administrator certificate,
	// executable auth plugin, impersonation or credential-bearing wrapper.
	probeConfig := &rest.Config{Host: s.config.Host, BearerToken: s.probeToken, TLSClientConfig: rest.TLSClientConfig{CAData: append([]byte(nil), s.config.CAData...), CAFile: s.config.CAFile, ServerName: s.config.ServerName}, RateLimiter: s.config.RateLimiter}
	probe, e := bootstrapProofClient(probeConfig, cluster, control)
	if e != nil {
		return e
	}
	raw, e := probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if e != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+p.Namespace.Name+":"+p.Account.Name || who.Status.UserInfo.UID != p.Account.UID {
		return cfg.ErrDenied
	}
	a := cfg.ConfigMapAdministration{Name: p.Guard.Name, SourceName: p.Marker.Name, ControlNamespace: control}
	for _, v := range s.desired.Administrators {
		a.Administrators = append(a.Administrators, cfg.KubernetesActor{Kind: v.Kind, Name: v.Name})
	}
	pin := GuardPin{PolicyUID: p.Guard.PolicyUID, PolicyGeneration: p.Guard.PolicyGeneration, BindingUID: p.Guard.BindingUID, BindingResourceVersion: p.Guard.BindingResourceVersion}
	proof, e := newConfigMapProtection(observer, probe, a, pin, "initial-bootstrap-continuity", initialBootstrapDenial)
	if e != nil {
		return e
	}
	policy, binding, e := InitialBootstrapAdmission(s.desired)
	if e != nil {
		return e
	}
	normalizePermissionPolicy(&policy.Spec)
	proof.policy, proof.binding = policy.Spec, binding.Spec
	s.proof = proof
	if e = s.current(ctx); e != nil {
		return e
	}
	return s.checkPrelude(ctx, p)
}

// Open creates only the finite public prelude and one private seed. Material is
// mandatory on first creation and may be absent for passive historical reopen.
// No role/provider credential or activation effect occurs here.
func (s *InitialBootstrap) Open(ctx context.Context, material *contracts.InitialBootstrapMaterial) (contracts.InitialBootstrapState, error) {
	var zero contracts.InitialBootstrapState
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer end()
	if e = s.administrator(bounded); e != nil {
		return zero, e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil && !apierrors.IsNotFound(e) {
		return zero, e
	}
	if apierrors.IsNotFound(e) {
		if s.seedUID != "" {
			return zero, cfg.ErrChanged
		}
		if _, e = s.namespace(bounded); e != nil {
			return zero, e
		}
		// A lost whole-install projection is never interpreted as a new setup.
		for _, path := range []string{"/api/v1/namespaces/" + s.desired.TargetNamespace, "/api/v1/namespaces/" + s.desired.BootstrapNamespace + "/configmaps/" + bootstrapNames(s.desired).root} {
			_, e = s.get(bounded, path)
			if !apierrors.IsNotFound(e) {
				return zero, cfg.ErrChanged
			}
		}
		if material == nil {
			return zero, ErrInitialBootstrapMaterialRequired
		}
		if !bootstrapMaterialValid(*material) || !time.Now().Before(material.StorageUseUntil) {
			return zero, cfg.ErrUnavailable
		}
		p, e := s.publicPrelude(bounded)
		if e != nil {
			return zero, e
		}
		if s.routedPrelude != nil && !equalJSON(*s.routedPrelude, p) {
			return zero, cfg.ErrChanged
		}
		state, e = newBootstrapState(s.desired, p, *material)
		if e != nil {
			return zero, e
		}
		if e = s.qualify(bounded, p, state.ClusterID); e != nil {
			return zero, e
		}
		if e = s.validateFleet(state); e != nil {
			return zero, e
		}
		body, e := json.Marshal(state)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		defer clear(body)
		want := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: bootstrapMeta(s.desired, bootstrapNames(s.desired).seed), Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}}
		// Only the winner's retained random material can lead to later effects.
		raw, _ := s.api.Post().AbsPath("/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets").Param("fieldValidation", "Strict").Body(&want).MaxRetries(0).DoRaw(bounded)
		clear(raw)
		secret, state, e = s.readSeed(bounded)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	if material != nil && !state.Retired && !equalJSON(state.Material, material) {
		return zero, cfg.ErrChanged
	}
	if e = s.qualify(bounded, state.Prelude, state.ClusterID); e != nil {
		return zero, e
	}
	if e = s.validateFleet(state); e != nil {
		return zero, e
	}
	if state.SeedUID == "" {
		next := state
		next.SeedUID = string(secret.UID)
		if e = s.updateSeed(bounded, secret, state, next); e != nil {
			return zero, e
		}
		state = next
	}
	s.seedUID = state.SeedUID
	if e = s.current(bounded); e != nil {
		return zero, e
	}
	return state, nil
}

func (s *InitialBootstrap) fleet(state contracts.InitialBootstrapState) contracts.FleetSettings {
	return bootstrapFleet(s.desired, state.InstallationID, state.IssuerEpoch)
}
func (s *InitialBootstrap) validateFleet(state contracts.InitialBootstrapState) error {
	if s.proof == nil {
		return cfg.ErrInvalid
	}
	b, e := json.Marshal(s.fleet(state))
	var out contracts.FleetSettings
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = decodePermissionSpec(b, s.proof.observer.validator.fleetSchema, &out); e != nil {
		return cfg.ErrInvalid
	}
	return nil
}

// Empty cluster is confined to pre-seed guard continuity. Permission reads and
// exported authority projections still use NewPermissionClient with real IDs.
func bootstrapProofClient(config *rest.Config, cluster string, control cfg.NamespaceRef) (*PermissionClient, error) {
	if cluster != "" {
		return NewPermissionClient(config, cluster, control, time.Now)
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, err
	}
	return &PermissionClient{api: api, control: control, now: time.Now}, nil
}
