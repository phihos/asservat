package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// SmallOpenBaoPreparation owns one create-once private state. It never talks to
// Bao or creates its workload/PVC, and cannot authorize installation or recovery.
type SmallOpenBaoPreparation struct {
	api  rest.Interface
	plan contracts.SmallOpenBaoPlan
	now  func() time.Time
}

func NewSmallOpenBaoPreparation(config *rest.Config, plan contracts.SmallOpenBaoPlan) (*SmallOpenBaoPreparation, error) {
	if !plan.Valid() {
		return nil, cfg.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	return &SmallOpenBaoPreparation{api: api, plan: plan, now: time.Now}, nil
}
func (s *SmallOpenBaoPreparation) current(ctx context.Context) bool {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	end, ok := ctx.Deadline()
	return ok && s.now().Before(end)
}
func (s *SmallOpenBaoPreparation) secretPath() string {
	return "/api/v1/namespaces/" + s.plan.Namespace + "/secrets/" + s.plan.StateSecretName()
}
func (s *SmallOpenBaoPreparation) pvcPath() string {
	return "/api/v1/namespaces/" + s.plan.Namespace + "/persistentvolumeclaims/" + s.plan.DataPVCName()
}
func (s *SmallOpenBaoPreparation) stateMetadata(m meta.ObjectMeta) (string, string, bool) {
	backend := m.Annotations[contracts.SmallOpenBaoBackendAnnotation]
	ready := m.Annotations[contracts.SmallOpenBaoReadyAnnotation]
	count := 1
	if ready != "" {
		count++
	}
	if m.Name != s.plan.StateSecretName() || m.Namespace != s.plan.Namespace || !authorization.UUID(string(m.UID)) || m.ResourceVersion == "" || m.DeletionTimestamp != nil || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 || len(m.Labels) != 1 || m.Labels["asservat.io/private-role"] != "small-openbao" || len(m.Annotations) != count || !authorization.UUID(backend) {
		return "", "", false
	}
	if ready == "" {
		return backend, "", true
	}
	parts := strings.Split(ready, "/")
	if len(parts) != 2 || parts[0] != backend || !authorization.UUID(parts[1]) {
		return "", "", false
	}
	return backend, parts[1], true
}
func (s *SmallOpenBaoPreparation) validState(v *core.Secret) bool {
	if v == nil {
		return false
	}
	backend, _, ok := s.stateMetadata(v.ObjectMeta)
	return ok && v.APIVersion == "v1" && v.Kind == "Secret" && v.Immutable != nil && *v.Immutable && v.Type == core.SecretTypeOpaque && len(v.StringData) == 0 && backend == string(v.Data[contracts.SmallOpenBaoBackendKey]) && ValidateSmallOpenBaoMaterial(s.plan, v.Data, s.now()) == nil
}
func (s *SmallOpenBaoPreparation) read(ctx context.Context) (*core.Secret, error) {
	raw, err := s.api.Get().AbsPath(s.secretPath()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	var v core.Secret
	if !s.current(ctx) || len(raw) > 2*contracts.SmallOpenBaoStateLimit || strictGuardJSON(raw, &v) != nil || !s.validState(&v) {
		clearSmallOpenBaoMaterial(v.Data)
		return nil, cfg.ErrUnavailable
	}
	return &v, nil
}
func (s *SmallOpenBaoPreparation) metadata(ctx context.Context, path, name string) (*meta.PartialObjectMetadata, error) {
	raw, err := s.api.Get().AbsPath(path).SetHeader("Accept", capacityMetadataAccept).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	return s.decodeMetadata(ctx, raw, name)
}
func (s *SmallOpenBaoPreparation) decodeMetadata(ctx context.Context, raw []byte, name string) (*meta.PartialObjectMetadata, error) {
	var v meta.PartialObjectMetadata
	if !s.current(ctx) || len(raw) > 32<<10 || strictGuardJSON(raw, &v) != nil || v.APIVersion != "meta.k8s.io/v1" || v.Kind != "PartialObjectMetadata" || v.Name != name || v.Namespace != s.plan.Namespace || !authorization.UUID(string(v.UID)) || v.ResourceVersion == "" || v.DeletionTimestamp != nil {
		return nil, cfg.ErrUnavailable
	}
	return &v, nil
}
func (s *SmallOpenBaoPreparation) absentWorkload(ctx context.Context) error {
	for _, path := range []string{"/apis/apps/v1/namespaces/" + s.plan.Namespace + "/statefulsets/" + s.plan.ServiceName(), "/api/v1/namespaces/" + s.plan.Namespace + "/pods/" + s.plan.ServiceName() + "-0"} {
		raw, err := s.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
		clear(raw)
		if !apierrors.IsNotFound(err) || !s.current(ctx) {
			return cfg.ErrUnavailable
		}
	}
	return nil
}
func (s *SmallOpenBaoPreparation) retainedData(ctx context.Context, readyPVC string) error {
	pvc, err := s.metadata(ctx, s.pvcPath(), s.plan.DataPVCName())
	if !s.current(ctx) {
		return cfg.ErrUnavailable
	}
	if err == nil {
		if readyPVC != "" && readyPVC != string(pvc.UID) {
			return cfg.ErrUnavailable
		}
		return nil
	}
	if readyPVC != "" || !apierrors.IsNotFound(err) {
		return cfg.ErrUnavailable
	}
	return s.absentWorkload(ctx)
}
func (s *SmallOpenBaoPreparation) prepared(v *core.Secret) contracts.SmallOpenBaoPrepared {
	backend, pvc, _ := s.stateMetadata(v.ObjectMeta)
	return contracts.SmallOpenBaoPrepared{State: contracts.WorkerObjectReference{Name: v.Name, UID: string(v.UID)}, BackendID: backend, RootsPEM: bytes.Clone(v.Data["ca.crt"]), ReadyPVCUID: pvc}
}

// Prepare generates at most once in this invocation, after named absence
// checks. An uncertain CREATE permits only exact same-byte readback.
func (s *SmallOpenBaoPreparation) Prepare(ctx context.Context) (contracts.SmallOpenBaoPrepared, error) {
	var zero contracts.SmallOpenBaoPrepared
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	state, err := s.read(ctx)
	if err == nil {
		defer clearSmallOpenBaoMaterial(state.Data)
		_, ready, _ := s.stateMetadata(state.ObjectMeta)
		if s.retainedData(ctx, ready) != nil || !s.current(ctx) {
			return zero, cfg.ErrUnavailable
		}
		return s.prepared(state), nil
	}
	if !apierrors.IsNotFound(err) || !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	raw, e := s.api.Get().AbsPath(s.pvcPath()).MaxRetries(0).DoRaw(ctx)
	clear(raw)
	if !apierrors.IsNotFound(e) || !s.current(ctx) || s.absentWorkload(ctx) != nil {
		return zero, cfg.ErrUnavailable
	}
	data, e := BuildSmallOpenBaoMaterial(s.plan, s.now())
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clearSmallOpenBaoMaterial(data)
	request := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.StateSecretName(), Namespace: s.plan.Namespace, Labels: map[string]string{"asservat.io/private-role": "small-openbao"}, Annotations: map[string]string{contracts.SmallOpenBaoBackendAnnotation: string(data[contracts.SmallOpenBaoBackendKey])}}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}
	body, e := json.Marshal(request)
	if e != nil || !s.current(ctx) {
		clear(body)
		return zero, cfg.ErrUnavailable
	}
	defer clear(body)
	answer, createErr := s.api.Post().AbsPath("/api/v1/namespaces/"+s.plan.Namespace+"/secrets").Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(answer)
	if !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	unknown := createErr != nil
	if !unknown {
		var v core.Secret
		if len(answer) > 2*contracts.SmallOpenBaoStateLimit || strictGuardJSON(answer, &v) != nil || !s.validState(&v) {
			clearSmallOpenBaoMaterial(v.Data)
			unknown = true
		} else {
			state = &v
		}
	}
	if unknown {
		if !s.current(ctx) {
			return zero, cfg.ErrUnavailable
		}
		state, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	defer clearSmallOpenBaoMaterial(state.Data)
	_, ready, _ := s.stateMetadata(state.ObjectMeta)
	if !sameSmallSeaweedData(state.Data, data) || ready != "" || !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	return s.prepared(state), nil
}

// MarkReady is called only after trusted setup independently verifies the
// final provider marker. This metadata receipt grants no application authority.
// It pins the original PVC permanently without reading seal/private CA keys.
func (s *SmallOpenBaoPreparation) MarkReady(ctx context.Context, state contracts.WorkerObjectReference, backendID string) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if !s.current(ctx) || state.Name != s.plan.StateSecretName() || !authorization.UUID(state.UID) || !authorization.UUID(backendID) {
		return zero, cfg.ErrUnavailable
	}
	m, err := s.metadata(ctx, s.secretPath(), state.Name)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	backend, ready, ok := s.stateMetadata(m.ObjectMeta)
	if !ok || string(m.UID) != state.UID || backend != backendID {
		return zero, cfg.ErrUnavailable
	}
	pvc, err := s.metadata(ctx, s.pvcPath(), s.plan.DataPVCName())
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	ref := contracts.WorkerObjectReference{Name: pvc.Name, UID: string(pvc.UID)}
	if ready != "" {
		if ready != ref.UID || !s.current(ctx) {
			return zero, cfg.ErrUnavailable
		}
		return ref, nil
	}
	wanted := backendID + "/" + ref.UID
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": m.UID, "resourceVersion": m.ResourceVersion, "annotations": map[string]string{contracts.SmallOpenBaoReadyAnnotation: wanted}}})
	if !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	raw, writeErr := s.api.Patch(types.MergePatchType).AbsPath(s.secretPath()).SetHeader("Accept", capacityMetadataAccept).Param("fieldValidation", "Strict").Body(patch).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	if writeErr == nil {
		m, err = s.decodeMetadata(ctx, raw, state.Name)
	}
	if writeErr != nil || err != nil {
		if !s.current(ctx) {
			return zero, cfg.ErrUnavailable
		}
		m, err = s.metadata(ctx, s.secretPath(), state.Name)
	}
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	backend, ready, ok = s.stateMetadata(m.ObjectMeta)
	if !ok || string(m.UID) != state.UID || backend != backendID || ready != ref.UID || !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	// A replacement during the CAS cannot be acknowledged as the original
	// initialized backend. The pinned annotation is never rewritten.
	currentPVC, err := s.metadata(ctx, s.pvcPath(), s.plan.DataPVCName())
	if err != nil || string(currentPVC.UID) != ref.UID || !s.current(ctx) {
		return zero, cfg.ErrUnavailable
	}
	return ref, nil
}
