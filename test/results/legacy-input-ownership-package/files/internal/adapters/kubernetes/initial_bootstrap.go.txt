package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// InitialBootstrap is the trusted installation prelude. It cannot activate a
// database, manufacture recovery authority, or accept arbitrary object bodies.
// Every live method is bound to the original parent and joined by Close.
type InitialBootstrap struct {
	desired       contracts.InitialBootstrap
	config        *rest.Config
	api           rest.Interface
	root          context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed, busy  bool
	joined        sync.WaitGroup
	seedUID       string
	routedPrelude *contracts.InitialBootstrapPrelude
	probeToken    string
	probeUntil    time.Time
	proof         *configMapProtection
}

func NewInitialBootstrap(ctx context.Context, config *rest.Config, d contracts.InitialBootstrap) (*InitialBootstrap, error) {
	if ctx == nil || ctx.Err() != nil || validateBootstrap(d) != nil {
		return nil, cfg.ErrInvalid
	}
	api, e := newBoundedAPI(config)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(d.Kubernetes.Endpoint)
	actual := api.Get().URL()
	if e != nil || u.Scheme != actual.Scheme || u.Host != actual.Host || u.Path != "" && u.Path != "/" {
		return nil, cfg.ErrInvalid
	}
	b, e := json.Marshal(d)
	var cloned contracts.InitialBootstrap
	if e != nil || json.Unmarshal(b, &cloned) != nil {
		return nil, cfg.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	return &InitialBootstrap{desired: cloned, config: rest.CopyConfig(config), api: api, root: root, cancel: cancel}, nil
}

func (s *InitialBootstrap) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
	s.mu.Lock()
	s.probeToken = ""
	s.mu.Unlock()
}
func (s *InitialBootstrap) enter(ctx context.Context) (context.Context, func(), error) {
	if s == nil || ctx == nil {
		return nil, nil, cfg.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root.Err() != nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	if s.busy {
		return nil, nil, cfg.ErrUnavailable
	}
	s.busy = true
	s.joined.Add(1)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	stop := context.AfterFunc(s.root, cancel)
	return bounded, func() {
		stop()
		cancel()
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		s.joined.Done()
	}, nil
}

func (s *InitialBootstrap) administrator(ctx context.Context) error {
	raw, e := s.api.Post().AbsPath("/apis/authentication.k8s.io/v1/selfsubjectreviews").Body(&auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}).MaxRetries(0).DoRaw(ctx)
	var who auth.SelfSubjectReview
	if e != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return cfg.ErrUnavailable
	}
	for _, a := range s.desired.Administrators {
		if actorMatches(cfg.KubernetesActor{Kind: a.Kind, Name: a.Name}, who.Status.UserInfo) {
			return nil
		}
	}
	return cfg.ErrDenied
}
func (s *InitialBootstrap) get(ctx context.Context, path string) ([]byte, error) {
	b, e := s.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		return nil, e
	}
	if permissionJSON(b, permissionPageBytes, 131072) != nil {
		clear(b)
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}
func (s *InitialBootstrap) namespace(ctx context.Context) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	b, e := s.get(ctx, "/api/v1/namespaces/"+s.desired.BootstrapNamespace)
	if e != nil {
		return zero, e
	}
	var ns core.Namespace
	if strictGuardJSON(b, &ns) != nil || ns.Name != s.desired.BootstrapNamespace || !authorization.UUID(string(ns.UID)) || ns.DeletionTimestamp != nil || ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" || len(ns.OwnerReferences) != 0 {
		return zero, cfg.ErrChanged
	}
	return contracts.WorkerObjectReference{Name: ns.Name, UID: string(ns.UID)}, nil
}

func bootstrapObjectMetadata(o runtime.Object) *meta.ObjectMeta {
	switch v := o.(type) {
	case *core.ServiceAccount:
		return &v.ObjectMeta
	case *core.Secret:
		return &v.ObjectMeta
	}
	return preparerMetadata(o)
}
func bootstrapObjectMatches(want, got runtime.Object) bool {
	w, m := bootstrapObjectMetadata(want), bootstrapObjectMetadata(got)
	if w == nil || m == nil || w.Name != m.Name || w.Namespace != m.Namespace || !authorization.UUID(string(m.UID)) || !identity.Text(m.ResourceVersion, 128) || m.DeletionTimestamp != nil || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 {
		return false
	}
	copy := got.DeepCopyObject()
	c := bootstrapObjectMetadata(copy)
	c.UID = ""
	c.ResourceVersion = ""
	c.Generation = 0
	c.CreationTimestamp = meta.Time{}
	c.ManagedFields = nil
	if p, ok := copy.(*admission.ValidatingAdmissionPolicy); ok {
		p.Status = admission.ValidatingAdmissionPolicyStatus{}
		normalizePermissionPolicy(&p.Spec)
	}
	wantCopy := want.DeepCopyObject()
	if p, ok := wantCopy.(*admission.ValidatingAdmissionPolicy); ok {
		normalizePermissionPolicy(&p.Spec)
	}
	return equalJSON(wantCopy, copy)
}

// Only the fixed public prelude calls this before protection. Private callers
// must first retain their exact create intent under the checked seed CAS.
func (s *InitialBootstrap) ensureObject(ctx context.Context, path string, want runtime.Object) (runtime.Object, error) {
	m := bootstrapObjectMetadata(want)
	if m == nil {
		return nil, cfg.ErrInvalid
	}
	full := path + "/" + m.Name
	raw, e := s.get(ctx, full)
	if apierrors.IsNotFound(e) {
		if e = s.administrator(ctx); e != nil {
			return nil, e
		}
		raw, e = s.api.Post().AbsPath(path).Param("fieldValidation", "Strict").Body(want).MaxRetries(0).DoRaw(ctx)
		if e != nil {
			// Exact named public/immutable CREATE is read-only recovered once.
			// An absent result never becomes a receipt or a successful effect.
			raw, e = s.get(ctx, full)
		}
	}
	defer clear(raw)
	if e != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil {
		return nil, cfg.ErrUnavailable
	}
	// Decode into a new zero concrete value, never request defaults.
	got := bootstrapEmptyObject(want)
	if got == nil || strictGuardJSON(raw, got) != nil || !bootstrapObjectMatches(want, got) || ctx.Err() != nil {
		return nil, cfg.ErrChanged
	}
	return got, nil
}

func bootstrapEmptyObject(want runtime.Object) runtime.Object {
	switch want.(type) {
	case *core.ServiceAccount:
		return &core.ServiceAccount{}
	case *core.Secret:
		return &core.Secret{}
	case *core.ConfigMap:
		return &core.ConfigMap{}
	case *rbac.Role:
		return &rbac.Role{}
	case *rbac.RoleBinding:
		return &rbac.RoleBinding{}
	case *admission.ValidatingAdmissionPolicy:
		return &admission.ValidatingAdmissionPolicy{}
	case *admission.ValidatingAdmissionPolicyBinding:
		return &admission.ValidatingAdmissionPolicyBinding{}
	default:
		return nil
	}
}

func (s *InitialBootstrap) readSeed(ctx context.Context) (*core.Secret, contracts.InitialBootstrapState, error) {
	var state contracts.InitialBootstrapState
	n := bootstrapNames(s.desired)
	raw, e := s.get(ctx, "/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets/"+n.seed)
	defer clear(raw)
	if e != nil {
		return nil, state, e
	}
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return nil, state, cfg.ErrChanged
	}
	for _, b := range secret.Data {
		defer clear(b)
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != core.SecretTypeOpaque || secret.Name != n.seed || secret.Namespace != s.desired.BootstrapNamespace || !authorization.UUID(string(secret.UID)) || !identity.Text(secret.ResourceVersion, 128) || secret.DeletionTimestamp != nil || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || secret.Immutable != nil && *secret.Immutable || len(secret.Data) != 1 || len(secret.StringData) != 0 {
		return nil, state, cfg.ErrChanged
	}
	state, e = contracts.DecodeInitialBootstrapState(bytes.NewReader(secret.Data["state.json"]))
	if e != nil || !bootstrapStateValid(s.desired, state) || state.SeedUID != "" && state.SeedUID != string(secret.UID) || s.seedUID != "" && s.seedUID != string(secret.UID) || !equalJSON(secret.Annotations, bootstrapSeedAnnotations(s.desired, state)) {
		return nil, contracts.InitialBootstrapState{}, cfg.ErrChanged
	}
	// Keep no aliased secret byte slice after its explicit clearing above.
	secret.Data = nil
	return &secret, state, nil
}

func (s *InitialBootstrap) updateSeed(ctx context.Context, secret *core.Secret, old, next contracts.InitialBootstrapState) error {
	if secret == nil || s.proof == nil || !bootstrapStateTransition(s.desired, old, next) {
		return cfg.ErrInvalid
	}
	if e := s.current(ctx); e != nil {
		return e
	}
	body, e := json.Marshal(next)
	if e != nil {
		return cfg.ErrInvalid
	}
	defer clear(body)
	copy := secret.DeepCopy()
	copy.Data = map[string][]byte{"state.json": body}
	copy.Annotations = bootstrapSeedAnnotations(s.desired, next)
	raw, e := s.api.Put().AbsPath("/api/v1/namespaces/"+s.desired.BootstrapNamespace+"/secrets/"+secret.Name).Param("fieldValidation", "Strict").Body(copy).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return cfg.ErrUnavailable
	}
	var observed core.Secret
	if strictGuardJSON(raw, &observed) != nil || observed.UID != secret.UID || observed.ResourceVersion == secret.ResourceVersion || !identity.Text(observed.ResourceVersion, 128) {
		return cfg.ErrChanged
	}
	for _, b := range observed.Data {
		defer clear(b)
	}
	actual, e := contracts.DecodeInitialBootstrapState(bytes.NewReader(observed.Data["state.json"]))
	if e != nil || !equalJSON(actual, next) || !equalJSON(observed.Annotations, copy.Annotations) {
		return cfg.ErrChanged
	}
	return s.current(ctx)
}

func (s *InitialBootstrap) current(ctx context.Context) error {
	if s.proof == nil || ctx.Err() != nil || !time.Now().Before(s.probeUntil) {
		return cfg.ErrUnavailable
	}
	if e := s.administrator(ctx); e != nil {
		return e
	}
	_, until, e := s.proof.current(ctx)
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) || !time.Now().Before(s.probeUntil) {
		return cfg.ErrUnavailable
	}
	return nil
}

// ProbeToken is only for the exact existing initial-schema/initial-prepare
// fixed private projection. It never supplies a setup interval or effect proof.
func (s *InitialBootstrap) ProbeToken(ctx context.Context) (string, time.Time, error) {
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return "", time.Time{}, e
	}
	defer end()
	if e = s.current(bounded); e != nil {
		return "", time.Time{}, e
	}
	return s.probeToken, s.probeUntil, nil
}

func bootstrapProbeMarker(d contracts.InitialBootstrap, name string) *core.ConfigMap {
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: bootstrapMeta(d, name), Data: map[string]string{"purpose": "Asservat independent bootstrap observation"}}
}
func bootstrapProbeAnchor(d contracts.InitialBootstrap) *core.Secret {
	return &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: bootstrapMeta(d, bootstrapNames(d).anchor), Type: core.SecretTypeOpaque, Immutable: ptr.To(true)}
}
