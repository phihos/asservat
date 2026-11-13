package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// SmallSeaweedPreparation is a create-only finite infrastructure administrator.
// It neither creates provider workloads/PVCs nor activates a bucket/root.
type SmallSeaweedPreparation struct {
	api  rest.Interface
	plan contracts.SmallSeaweedPlan
	now  func() time.Time
}

func NewSmallSeaweedPreparation(config *rest.Config, p contracts.SmallSeaweedPlan) (*SmallSeaweedPreparation, error) {
	if !p.Valid() {
		return nil, cfg.ErrInvalid
	}
	api, e := newBoundedAPI(config)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	return &SmallSeaweedPreparation{api: api, plan: p, now: time.Now}, nil
}
func (s *SmallSeaweedPreparation) secretPath(name string) string {
	return "/api/v1/namespaces/" + s.plan.Namespace + "/secrets/" + name
}
func (s *SmallSeaweedPreparation) readSecret(ctx context.Context, name string) (*core.Secret, error) {
	raw, e := s.api.Get().AbsPath(s.secretPath(name)).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return nil, e
	}
	limit := 2 << 20
	if name == s.plan.StateSecretName() {
		limit = contracts.SmallSeaweedStateLimit
	}
	var secret core.Secret
	if len(raw) > limit || strictGuardJSON(raw, &secret) != nil {
		return nil, seaweedProviderFailure("prepare-decode")
	}
	return &secret, nil
}
func (s *SmallSeaweedPreparation) metadata(secret *core.Secret, name, role string) bool {
	return secret != nil && secret.Name == name && secret.Namespace == s.plan.Namespace && authorization.UUID(string(secret.UID)) && secret.ResourceVersion != "" && secret.DeletionTimestamp == nil && len(secret.OwnerReferences) == 0 && len(secret.Finalizers) == 0 && len(secret.StringData) == 0 && secret.Type == core.SecretTypeOpaque && len(secret.Labels) == 1 && secret.Labels["asservat.io/private-role"] == role
}
func (s *SmallSeaweedPreparation) validState(secret *core.Secret) bool {
	return s.metadata(secret, s.plan.StateSecretName(), "small-seaweed") && secret.Immutable != nil && *secret.Immutable && len(secret.Annotations) == 0 && ValidateSmallSeaweedMaterial(s.plan, secret.Data, s.now()) == nil
}

// smallSeaweedStateAnnotation binds an IAM Secret to the state of the
// installer-era binder (small_seaweed_binding.go), removed in slice 4.
const smallSeaweedStateAnnotation = "asservat.io/backend-state-uid"

func (s *SmallSeaweedPreparation) validIAM(secret, state *core.Secret, original []byte) bool {
	return s.metadata(secret, s.plan.IAMSecretName(), "small-seaweed-iam") && (secret.Immutable == nil || !*secret.Immutable) && len(secret.Annotations) == 1 && secret.Annotations[smallSeaweedStateAnnotation] == string(state.UID) && len(secret.Data) == 1 && providerconfig.ValidateSeaweedConfigTransition(original, secret.Data[providerconfig.SeaweedConfigKey]) == nil
}
func sameSmallSeaweedData(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, v := range a {
		if !bytes.Equal(v, b[name]) {
			return false
		}
	}
	return true
}

// createOnce acknowledges only the same original bytes, including after an
// uncertain reply. It performs at most one create and one exact GET readback.
func (s *SmallSeaweedPreparation) createOnce(ctx context.Context, request *core.Secret) (*core.Secret, error) {
	raw, e := json.Marshal(request)
	if e != nil {
		return nil, seaweedProviderFailure("prepare-encoding")
	}
	defer clear(raw)
	response, e := s.api.Post().AbsPath("/api/v1/namespaces/"+s.plan.Namespace+"/secrets").Param("fieldValidation", "Strict").Body(raw).MaxRetries(0).DoRaw(ctx)
	defer clear(response)
	var actual *core.Secret
	if e == nil {
		var decoded core.Secret
		if len(response) > 2<<20 || strictGuardJSON(response, &decoded) != nil {
			return nil, seaweedProviderFailure("prepare-create-answer")
		}
		actual = &decoded
	} else {
		actual, e = s.readSecret(ctx, request.Name)
		if e != nil {
			return nil, seaweedProviderFailure("prepare-create-unknown")
		}
	}
	if !sameSmallSeaweedData(actual.Data, request.Data) || ctx.Err() != nil {
		clearSmallSeaweedData(actual.Data)
		return nil, seaweedProviderFailure("prepare-create-mismatch")
	}
	return actual, nil
}

// Prepare creates the private state once. The IAM configuration is compiled
// separately from the complete principal set by the secrets hook.
func (s *SmallSeaweedPreparation) Prepare(ctx context.Context) (contracts.SmallSeaweedPrepared, error) {
	var zero contracts.SmallSeaweedPrepared
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, seaweedProviderFailure("prepare-input")
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	state, e := s.readSecret(ctx, s.plan.StateSecretName())
	if apierrors.IsNotFound(e) {
		data, buildErr := BuildSmallSeaweedMaterial(s.plan, s.now())
		if buildErr != nil {
			return zero, seaweedProviderFailure("prepare-material")
		}
		defer clearSmallSeaweedData(data)
		state, e = s.createOnce(ctx, &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.StateSecretName(), Namespace: s.plan.Namespace, Labels: map[string]string{"asservat.io/private-role": "small-seaweed"}}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data})
	}
	if e != nil || !s.validState(state) {
		if state != nil {
			clearSmallSeaweedData(state.Data)
		}
		return zero, seaweedProviderFailure("prepare-state")
	}
	defer clearSmallSeaweedData(state.Data)
	admin, e := decodeSmallSeaweedAdmin(state.Data[contracts.SmallSeaweedAdminKey])
	if e != nil || ctx.Err() != nil {
		return zero, seaweedProviderFailure("prepare-administrator")
	}
	return contracts.SmallSeaweedPrepared{State: contracts.WorkerObjectReference{Name: state.Name, UID: string(state.UID)}, BackendID: string(state.Data[contracts.SmallSeaweedBackendKey]), InitializationID: string(state.Data[contracts.SmallSeaweedInitializationKey]), RootsPEM: bytes.Clone(state.Data["ca.crt"]), Admin: admin}, nil
}
