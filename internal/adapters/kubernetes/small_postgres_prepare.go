package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// SmallPostgresPreparation is a finite infrastructure administrator, not a
// runtime identity, installation witness or database recovery controller.
type SmallPostgresPreparation struct {
	api  rest.Interface
	plan contracts.SmallPostgresPlan
	now  func() time.Time
}

func NewSmallPostgresPreparation(config *rest.Config, p contracts.SmallPostgresPlan) (*SmallPostgresPreparation, error) {
	if !p.Valid() {
		return nil, cfg.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	return &SmallPostgresPreparation{api: api, plan: p, now: time.Now}, nil
}

func (s *SmallPostgresPreparation) secretPath() string {
	return "/api/v1/namespaces/" + s.plan.Namespace + "/secrets/" + s.plan.StateSecretName()
}

func (s *SmallPostgresPreparation) validSecret(v *core.Secret) bool {
	return v != nil && v.APIVersion == "v1" && v.Kind == "Secret" && v.Name == s.plan.StateSecretName() && v.Namespace == s.plan.Namespace && authorization.UUID(string(v.UID)) && v.ResourceVersion != "" && v.DeletionTimestamp == nil && len(v.OwnerReferences) == 0 && len(v.Finalizers) == 0 && v.Immutable != nil && *v.Immutable && v.Type == core.SecretTypeOpaque && len(v.StringData) == 0 && len(v.Labels) == 1 && v.Labels["asservat.io/private-role"] == "small-postgres" && ValidateSmallPostgresMaterial(s.plan, v.Data, s.now()) == nil
}

func (s *SmallPostgresPreparation) read(ctx context.Context) (*core.Secret, error) {
	raw, err := s.api.Get().AbsPath(s.secretPath()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	var v core.Secret
	if len(raw) > 96<<10 || strictGuardJSON(raw, &v) != nil || !s.validSecret(&v) {
		return nil, cfg.ErrInvalid
	}
	return &v, nil
}

func smallPostgresClear(d map[string][]byte) {
	for _, b := range d {
		clear(b)
	}
}

// A retained workload with missing data is recovery, not another initdb. If
// Helm never reached workload/PVC creation, the original create-once state can
// still complete its first installation. Absence or errors never prove loss
// was recovered, and this check cannot detect historical replacement of a PVC.
func (s *SmallPostgresPreparation) checkRetainedData(ctx context.Context) error {
	base := "/api/v1/namespaces/" + s.plan.Namespace
	raw, err := s.api.Get().AbsPath(base + "/persistentvolumeclaims/" + s.plan.DataPVCName()).MaxRetries(0).DoRaw(ctx)
	clear(raw)
	if ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return cfg.ErrUnavailable
	}
	paths := []string{"/apis/apps/v1/namespaces/" + s.plan.Namespace + "/statefulsets/" + s.plan.ServiceName(), base + "/pods/" + s.plan.ServiceName() + "-0"}
	if s.plan.Keycloak {
		paths = append(paths, "/apis/apps/v1/namespaces/"+s.plan.Namespace+"/deployments/"+s.plan.Name+"-keycloak")
	}
	for _, path := range paths {
		raw, err = s.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
		clear(raw)
		if !apierrors.IsNotFound(err) || ctx.Err() != nil {
			return cfg.ErrUnavailable
		}
	}
	return nil
}

// Prepare performs no SQL effects. An unknown CREATE permits only one exact
// readback; it never regenerates, overwrites or retries CREATE in this call.
func (s *SmallPostgresPreparation) Prepare(ctx context.Context) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	old, err := s.read(ctx)
	if err == nil {
		defer smallPostgresClear(old.Data)
		if s.checkRetainedData(ctx) != nil || ctx.Err() != nil {
			return zero, cfg.ErrUnavailable
		}
		return contracts.WorkerObjectReference{Name: old.Name, UID: string(old.UID)}, nil
	}
	if !apierrors.IsNotFound(err) {
		return zero, cfg.ErrUnavailable
	}
	for _, name := range []string{s.plan.DataPVCName(), s.plan.BackupPVCName()} {
		raw, e := s.api.Get().AbsPath("/api/v1/namespaces/" + s.plan.Namespace + "/persistentvolumeclaims/" + name).MaxRetries(0).DoRaw(ctx)
		clear(raw)
		if !apierrors.IsNotFound(e) {
			return zero, cfg.ErrUnavailable
		}
	}
	data, err := BuildSmallPostgresMaterial(s.plan, s.now())
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer smallPostgresClear(data)
	secret := &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.StateSecretName(), Namespace: s.plan.Namespace, Labels: map[string]string{"asservat.io/private-role": "small-postgres"}}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}
	body, err := json.Marshal(secret)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(body)
	raw, createErr := s.api.Post().AbsPath("/api/v1/namespaces/"+s.plan.Namespace+"/secrets").Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var actual *core.Secret
	if createErr == nil {
		var got core.Secret
		if len(raw) > 96<<10 || strictGuardJSON(raw, &got) != nil || !s.validSecret(&got) {
			return zero, cfg.ErrUnavailable
		}
		actual = &got
	} else {
		actual, err = s.read(ctx)
		if err != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	defer smallPostgresClear(actual.Data)
	if len(actual.Data) != len(data) || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	for k, v := range data {
		if !bytes.Equal(v, actual.Data[k]) {
			return zero, cfg.ErrUnavailable
		}
	}
	return contracts.WorkerObjectReference{Name: actual.Name, UID: string(actual.UID)}, nil
}
