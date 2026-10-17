package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

// InitialCredentialStateStore is a trusted provisioning facet, not the
// activation Pod's client. It cannot create a namespace, guard, account or Pod.
// The independently pinned clean namespace must already have been established.
type InitialCredentialStateStore struct {
	protection                   *InitialWorkloadProtection
	inputUID, installation, name string
	plan                         artifact.Digest
}

func NewInitialCredentialStateStore(administrator, probe *PermissionClient, workload cfg.InitialWorkloadAdministration, pin GuardPin, inputUID, installation, name string, plan artifact.Digest) (*InitialCredentialStateStore, error) {
	if !authorization.UUID(inputUID) || !authorization.UUID(installation) || len(validation.IsDNS1123Subdomain(name)) != 0 || plan == (artifact.Digest{}) {
		return nil, cfg.ErrInvalid
	}
	g, err := NewInitialWorkloadProtection(administrator, probe, workload, pin)
	if err != nil {
		return nil, err
	}
	return &InitialCredentialStateStore{g, inputUID, installation, name, plan}, nil
}

// current proves the administrator, independent native enforcement and exact
// immutable startup inputs. Creating credentials additionally requires the
// original inert Pod; cleanup reads may proceed after that Pod terminated.
func (s *InitialCredentialStateStore) current(ctx context.Context, gated bool) (time.Time, error) {
	if s == nil || s.protection == nil || s.protection.guard == nil || ctx == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	g, p := s.protection, s.protection.plan
	start := g.guard.observer.now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	raw, err := g.guard.observer.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if err != nil || strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return time.Time{}, cfg.ErrUnavailable
	}
	allowed := false
	for _, actor := range p.Administrators {
		allowed = allowed || actorMatches(actor, who.Status.UserInfo)
	}
	for _, account := range []string{p.WriterAccount, p.ProbeAccount} {
		if who.Status.UserInfo.Username == "system:serviceaccount:"+p.ControlNamespace.Name+":"+account {
			allowed = false
		}
	}
	if !allowed {
		return time.Time{}, cfg.ErrDenied
	}
	if err = g.account(ctx, g.guard.probe, p.ProbeAccount, p.ProbeAccountUID, false); err != nil {
		return time.Time{}, err
	}
	_, until, err := g.guard.current(ctx)
	if err != nil {
		return time.Time{}, err
	}
	raw, err = g.guard.observer.raw(ctx, "/api/v1/namespaces/"+p.ControlNamespace.Name+"/configmaps/"+p.Configuration, nil)
	var input core.ConfigMap
	if err != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || json.Unmarshal(raw, &input) != nil || input.APIVersion != "v1" || input.Kind != "ConfigMap" || !ownerMetadata(input.ObjectMeta, p.ControlNamespace.Name, p.Configuration, s.inputUID) || input.Immutable == nil || !*input.Immutable || len(input.Data) != 1 || len(input.BinaryData) != 0 || len(input.OwnerReferences) != 0 {
		return time.Time{}, cfg.ErrChanged
	}
	c, err := contracts.DecodeInitialInstaller(bytes.NewBufferString(input.Data["deployment.json"]))
	if err != nil {
		return time.Time{}, cfg.ErrChanged
	}
	canonical, err := json.Marshal(c)
	if err != nil || artifact.Digest(sha256.Sum256(canonical)) != s.plan || !contracts.InitialInstallerFormatSupported(c.Format) || c.InstallationID != s.installation || c.ClusterID != g.guard.observer.clusterID || c.Namespace.Name != p.ControlNamespace.Name || c.Namespace.UID != p.ControlNamespace.UID || c.Configuration != p.Configuration || c.Pod.Name != p.PodName || c.Pod.UID != p.PodUID || c.PodSpecDigest != hex.EncodeToString(p.PodSpecDigest[:]) || c.WriterAccount.Name != p.WriterAccount || c.WriterAccount.UID != p.WriterAccountUID || c.ProbeAccount.Name != p.ProbeAccount || c.ProbeAccount.UID != p.ProbeAccountUID {
		return time.Time{}, cfg.ErrChanged
	}
	if gated {
		raw, err = g.guard.observer.raw(ctx, "/api/v1/namespaces/"+p.ControlNamespace.Name+"/serviceaccounts/"+p.WriterAccount, nil)
		var account core.ServiceAccount
		if err != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || json.Unmarshal(raw, &account) != nil || account.APIVersion != "v1" || account.Kind != "ServiceAccount" || !ownerMetadata(account.ObjectMeta, p.ControlNamespace.Name, p.WriterAccount, p.WriterAccountUID) {
			return time.Time{}, cfg.ErrChanged
		}
		raw, err = g.guard.observer.raw(ctx, "/api/v1/namespaces/"+p.ControlNamespace.Name+"/pods/"+p.PodName, nil)
		var pod core.Pod
		if err != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || json.Unmarshal(raw, &pod) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || !ownerMetadata(pod.ObjectMeta, p.ControlNamespace.Name, p.PodName, p.PodUID) || len(pod.OwnerReferences) != 0 || pod.Spec.ServiceAccountName != p.WriterAccount || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != InitialInstallerSchedulingGate || pod.Spec.RestartPolicy != core.RestartPolicyNever || pod.Status.Phase != "" && pod.Status.Phase != core.PodPending || InstallationPodSpecDigest(pod.Spec) != p.PodSpecDigest {
			return time.Time{}, cfg.ErrChanged
		}
	}
	ns, err := g.guard.observer.namespace(ctx, p.ControlNamespace)
	until = identity.Earlier(until, start.Add(5*time.Second))
	if parent, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, parent)
	}
	if err != nil || ns.Deleting || ctx.Err() != nil || !g.guard.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}

func (s *InitialCredentialStateStore) payload(raw []byte) bool {
	w, err := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(raw))
	return err == nil && w.Format == contracts.InitialSQLCredentialsFormat && w.InstallationID == s.installation && w.PlanDigest == hex.EncodeToString(s.plan[:])
}

func (s *InitialCredentialStateStore) secret(raw []byte, uid string) (*core.Secret, error) {
	var v core.Secret
	if permissionJSON(raw, 16<<10, 512) != nil || json.Unmarshal(raw, &v) != nil || v.APIVersion != "v1" || v.Kind != "Secret" || v.Type != core.SecretTypeOpaque || !authorization.UUID(string(v.UID)) || !ownerMetadata(v.ObjectMeta, s.protection.plan.ControlNamespace.Name, s.name, string(v.UID)) || uid != "" && string(v.UID) != uid || v.Immutable == nil || !*v.Immutable || len(v.OwnerReferences) != 0 || len(v.Data) != 1 || len(v.StringData) != 0 || !s.payload(v.Data["state.json"]) {
		for _, b := range v.Data {
			clear(b)
		}
		return nil, cfg.ErrChanged
	}
	return &v, nil
}

// Create sends at most one non-replayed POST. An uncertain reply or collision
// permits only exact-content lookup with the same caller-retained secret bytes.
// It never replaces a Secret, generates credentials or renews their validity.
func (s *InitialCredentialStateStore) Create(ctx context.Context, payload []byte) (contracts.WorkerObjectReference, error) {
	ref, _, err := s.createWithCompletion(ctx, payload)
	return ref, err
}

func (s *InitialCredentialStateStore) createWithCompletion(ctx context.Context, payload []byte) (ref contracts.WorkerObjectReference, closed bool, err error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil || len(payload) == 0 || len(payload) > 4096 {
		return zero, false, cfg.ErrInvalid
	}
	payload = append([]byte(nil), payload...)
	defer clear(payload)
	if !s.payload(payload) {
		return zero, false, cfg.ErrInvalid
	}
	until, err := s.current(ctx, true)
	if err != nil {
		return zero, false, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	v := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.name, Namespace: s.protection.plan.ControlNamespace.Name}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"state.json": payload}}
	encoded, err := json.Marshal(v)
	if err != nil {
		return zero, false, cfg.ErrInvalid
	}
	defer clear(encoded)
	path := "/api/v1/namespaces/" + v.Namespace + "/secrets"
	response := s.protection.guard.observer.api.Post().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(encoded).Do(ctx)
	code := 0
	response.StatusCode(&code)
	raw, err := response.Raw()
	positive := err == nil && code == 201
	if err == nil {
		err = response.Error()
	}
	positive = positive && err == nil
	defer func() { clear(raw) }()
	if err != nil {
		if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			return zero, false, cfg.ErrDenied
		}
		clear(raw)
		raw, err = s.protection.guard.observer.raw(ctx, path+"/"+s.name, nil)
		if err != nil {
			return zero, false, cfg.ErrUnavailable
		}
	}
	stored, err := s.secret(raw, "")
	if err != nil {
		return zero, false, err
	}
	defer clear(stored.Data["state.json"])
	if !bytes.Equal(stored.Data["state.json"], payload) {
		return zero, false, cfg.ErrChanged
	}
	ref = contracts.WorkerObjectReference{Name: s.name, UID: string(stored.UID)}
	closed = positive && ctx.Err() == nil && s.protection.guard.observer.now().Before(until)
	// A post-write observation detects concurrent source/guard changes but
	// never extends the original operation's deadline or returns new authority.
	if _, err = s.current(ctx, true); err != nil || ctx.Err() != nil || !s.protection.guard.observer.now().Before(until) {
		return ref, closed, cfg.ErrUnavailable
	}
	return ref, closed, nil
}

// Read requires the previously retained Secret UID, including during cleanup.
// The caller owns and must clear returned secret bytes. It must also validate
// the SQL plan before provisioning or retirement; persistence is not authority.
func (s *InitialCredentialStateStore) Read(ctx context.Context, ref contracts.WorkerObjectReference) ([]byte, error) {
	if s == nil || ctx == nil || ref.Name != s.name || !authorization.UUID(ref.UID) {
		return nil, cfg.ErrInvalid
	}
	until, err := s.current(ctx, false)
	if err != nil {
		return nil, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	raw, err := s.protection.guard.observer.raw(ctx, "/api/v1/namespaces/"+s.protection.plan.ControlNamespace.Name+"/secrets/"+s.name, nil)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	defer clear(raw)
	v, err := s.secret(raw, ref.UID)
	if err != nil {
		return nil, err
	}
	payload := v.Data["state.json"]
	if _, err = s.current(ctx, false); err != nil || ctx.Err() != nil || !s.protection.guard.observer.now().Before(until) {
		clear(payload)
		return nil, cfg.ErrUnavailable
	}
	return payload, nil
}

// ResolveCreate is exclusively a read of an original unresolved CREATE. Its
// caller must retain the original exact payload under its own durable one-use
// claim. Missing or mismatching state does not grant permission to send again.
func (s *InitialCredentialStateStore) ResolveCreate(ctx context.Context, payload []byte) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil || len(payload) == 0 || len(payload) > 4096 {
		return zero, cfg.ErrInvalid
	}
	payload = append([]byte(nil), payload...)
	defer clear(payload)
	if !s.payload(payload) {
		return zero, cfg.ErrInvalid
	}
	until, e := s.current(ctx, true)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	raw, e := s.protection.guard.observer.raw(ctx, "/api/v1/namespaces/"+s.protection.plan.ControlNamespace.Name+"/secrets/"+s.name, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	stored, e := s.secret(raw, "")
	if e != nil {
		return zero, e
	}
	defer clear(stored.Data["state.json"])
	if !bytes.Equal(stored.Data["state.json"], payload) {
		return zero, cfg.ErrChanged
	}
	if _, e = s.current(ctx, true); e != nil || ctx.Err() != nil || !s.protection.guard.observer.now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	return contracts.WorkerObjectReference{Name: s.name, UID: string(stored.UID)}, nil
}
