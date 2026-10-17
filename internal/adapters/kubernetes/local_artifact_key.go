package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

const localKeyConfigurationDenial = "asservat: local key configuration is protected"

// LocalArtifactKey is the installed key service's artifact key source
// (ADR-198): the configuration ConfigMap and its guard. The configuration
// pins the immutable key Secret by UID and SHA-256.
type LocalArtifactKey struct {
	Configuration contracts.WorkerObjectReference
	Guard         contracts.OwnerDeploymentGuard
}

// EnsureLocalArtifactKey generates the artifact root key once, from
// crypto/rand, as version 1 of an immutable Secret, then guards and creates
// the configuration naming it (ADR-198 decision 2). A rerun reopens the
// existing Secret by its digest and never generates again; an existing
// configuration must name exactly that Secret, key and epoch.
func EnsureLocalArtifactKey(ctx context.Context, config *rest.Config, control cfg.NamespaceRef, installation, keyID, recoveryEpoch string, admins []cfg.KubernetesActor) (LocalArtifactKey, error) {
	var out LocalArtifactKey
	scope := authorization.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: keyID}
	if ctx == nil || config == nil || control.Name == "" || !authorization.UUID(control.UID) || !scope.Valid() || !authorization.UUID(recoveryEpoch) || len(admins) == 0 {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	name := contracts.LocalArtifactKeySecretName(installation)
	secrets := api.CoreV1().Secrets(control.Name)
	secret, err := secrets.Get(call, name, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		secret, err = createLocalArtifactKey(call, secrets, name, scope)
	}
	if err != nil {
		return out, cfg.ErrUnavailable
	}
	payload := secret.Data["keys.json"]
	defer clear(payload)
	if secret.Type != core.SecretTypeOpaque || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil || len(secret.Data) != 1 || len(payload) == 0 || !authorization.UUID(string(secret.UID)) {
		return out, cfg.ErrChanged
	}
	sum := sha256.Sum256(payload)
	configName := contracts.LocalArtifactKeyConfigurationName(installation)
	policy, binding, err := configMapAdmission(cfg.ConfigMapAdministration{Name: configName + "-guard", SourceName: configName, ControlNamespace: control, Administrators: admins}, "protected-local-key-configuration", localKeyConfigurationDenial)
	if err != nil {
		return out, err
	}
	if out.Guard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}
	want, err := json.Marshal(contracts.LocalKeyConfiguration{Format: "asservat-local-key-configuration/v1", InstallationID: installation, Purpose: scope.Purpose, KeyID: keyID, RecoveryEpoch: recoveryEpoch, Revision: 1,
		Secret: contracts.LocalKeySecretReference{Name: name, UID: string(secret.UID), SHA256: hex.EncodeToString(sum[:])}})
	if err != nil {
		return out, cfg.ErrInvalid
	}
	configMaps := api.CoreV1().ConfigMaps(control.Name)
	c, err := configMaps.Create(call, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: configName}, Data: map[string]string{"keys.json": string(want)}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if c, err = configMaps.Get(call, configName, meta.GetOptions{}); err == nil && (len(c.Data) != 1 || !equalJSON(json.RawMessage(c.Data["keys.json"]), json.RawMessage(want))) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(c.UID)) {
		return out, cfg.ErrUnavailable
	}
	out.Configuration = contracts.WorkerObjectReference{Name: c.Name, UID: string(c.UID)}
	return out, nil
}

// createLocalArtifactKey writes the only copy of the generated material; the
// local buffers are cleared, the API client's copies are not under our control.
func createLocalArtifactKey(ctx context.Context, secrets typed.SecretInterface, name string, scope authorization.KeyScope) (*core.Secret, error) {
	material := make([]byte, 32)
	defer clear(material)
	if _, err := rand.Read(material); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{"format": "asservat-local-keys/v1", "installationID": scope.InstallationID, "purpose": scope.Purpose, "keyID": scope.KeyID, "activeVersion": 1,
		"keys": []any{map[string]any{"version": 1, "material": material}}})
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	s, err := secrets.Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"keys.json": payload}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// Another run created it: reopen, never replace.
		return secrets.Get(ctx, name, meta.GetOptions{})
	}
	return s, err
}
