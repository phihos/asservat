package kubernetes

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// SmallKeycloakStateStore is the finite preparation job's exact named-Secret
// port. It has no update/delete, broad list, or runtime authorization behavior.
type SmallKeycloakStateStore struct {
	api                                                rest.Interface
	namespace, name, databaseStateName, deploymentName string
	externalPresence                                   func(context.Context) (bool, error)
}

func NewSmallKeycloakStateStore(config *rest.Config, s contracts.SmallKeycloakSettings, databaseStateName, deploymentName string, externalPresence func(context.Context) (bool, error)) (*SmallKeycloakStateStore, error) {
	if len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(s.SecretName)) != 0 || databaseStateName != "" && len(validation.IsDNS1123Subdomain(databaseStateName)) != 0 || databaseStateName == s.SecretName || len(validation.IsDNS1123Subdomain(deploymentName)) != 0 || databaseStateName != "" && externalPresence != nil {
		return nil, cfg.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	return &SmallKeycloakStateStore{api: api, namespace: s.Namespace, name: s.SecretName, databaseStateName: databaseStateName, deploymentName: deploymentName, externalPresence: externalPresence}, nil
}

func (s *SmallKeycloakStateStore) path(name string) string {
	return "/api/v1/namespaces/" + s.namespace + "/secrets/" + name
}

func (s *SmallKeycloakStateStore) decode(raw []byte) (*core.Secret, error) {
	var v core.Secret
	if len(raw) > contracts.SmallKeycloakStateMaxBytes || strictGuardJSON(raw, &v) != nil {
		return nil, cfg.ErrInvalid
	}
	return &v, nil
}

func (s *SmallKeycloakStateStore) Read(ctx context.Context) (*core.Secret, error) {
	raw, err := s.api.Get().AbsPath(s.path(s.name)).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	return s.decode(raw)
}

func (s *SmallKeycloakStateStore) Create(ctx context.Context, v *core.Secret) (*core.Secret, error) {
	if v == nil || v.Namespace != s.namespace || v.Name != s.name {
		return nil, cfg.ErrInvalid
	}
	body, err := json.Marshal(v)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	defer clear(body)
	raw, err := s.api.Post().AbsPath("/api/v1/namespaces/"+s.namespace+"/secrets").Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	return s.decode(raw)
}

func (s *SmallKeycloakStateStore) DatabaseStateExists(ctx context.Context) (bool, error) {
	// A retained provider workload with missing original state is recovery.
	// Never fall through to database inspection or generate a replacement.
	raw, err := s.api.Get().AbsPath("/apis/apps/v1/namespaces/" + s.namespace + "/deployments/" + s.deploymentName).MaxRetries(0).DoRaw(ctx)
	clear(raw)
	if err == nil {
		return true, nil
	}
	if !apierrors.IsNotFound(err) || ctx.Err() != nil {
		return false, cfg.ErrUnavailable
	}
	if s.databaseStateName == "" {
		// An external database needs its own current positive empty-state
		// observation; Kubernetes absence does not supply one.
		if s.externalPresence == nil {
			return false, cfg.ErrUnavailable
		}
		return s.externalPresence(ctx)
	}
	raw, err = s.api.Get().AbsPath(s.path(s.databaseStateName)).MaxRetries(0).DoRaw(ctx)
	clear(raw)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
