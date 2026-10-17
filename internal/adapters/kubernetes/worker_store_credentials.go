package kubernetes

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
)

// The accepted administrator profile pins a previously provisioned immutable
// Secret. Observation checks that exact object, never adopts a same-name
// replacement and never writes or hashes credential contents into SQL/audit.
// Installation must protect initial creation and grant only named Secret reads.
func checkWorkerStoreSecret(ctx context.Context, client *PermissionClient, p value.DownloadWorkerProfile) error {
	if p.StoreCredentialSecret == "" {
		return nil
	}
	b, err := client.raw(ctx, "/api/v1/namespaces/"+p.Namespace+"/secrets/"+p.StoreCredentialSecret, nil)
	if err != nil {
		return artifact.ErrDownloadUnavailable
	}
	defer clear(b)
	var secret core.Secret
	if len(b) > 32<<10 || json.Unmarshal(b, &secret) != nil {
		return artifact.ErrInvalid
	}
	defer func() {
		for _, v := range secret.Data {
			clear(v)
		}
	}()
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Namespace != p.Namespace || secret.Name != p.StoreCredentialSecret || string(secret.UID) != p.StoreCredentialSecretUID || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil || secret.Immutable == nil || !*secret.Immutable || secret.Type != core.SecretTypeOpaque || len(secret.StringData) != 0 || len(secret.Data) != 1 || len(secret.Data["credentials.json"]) == 0 || len(secret.Data["credentials.json"]) > contracts.WorkerStoreCredentialsMaxBytes {
		return artifact.ErrInvalid
	}
	return nil
}
