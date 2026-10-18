package kubernetes

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// EnsureEvidenceDeleteSecret creates the immutable Secret holding the
// operator's evidence delete credential (ADR-205 decision 4) in the hub
// namespace, or reopens it when its one key is byte-identical. Only the
// hub-worker Pod projects it; no Role names it.
func EnsureEvidenceDeleteSecret(ctx context.Context, config *rest.Config, namespace, installation string, credential []byte) error {
	if ctx == nil || config == nil || !authorization.UUID(installation) || len(validation.IsDNS1123Label(namespace)) != 0 || len(credential) == 0 || len(credential) > 32<<10 {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	name := contracts.EvidenceDeleteCredentialName(installation)
	secrets := api.CoreV1().Secrets(namespace)
	s, err := secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.EvidenceDeleteCredentialFile: credential}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if s, err = secrets.Get(call, name, meta.GetOptions{}); err == nil && (s.Immutable == nil || !*s.Immutable || s.Type != core.SecretTypeOpaque || len(s.Data) != 1 || !bytes.Equal(s.Data[contracts.EvidenceDeleteCredentialFile], credential) || len(s.OwnerReferences) != 0 || s.DeletionTimestamp != nil) {
			return cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(s.UID)) {
		return cfg.ErrUnavailable
	}
	return nil
}
