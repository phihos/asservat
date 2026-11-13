package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// WorkerConfigurationSource reads the Helm-rendered worker profile of its
// client's namespace (the download-worker namespace).
type WorkerConfigurationSource struct {
	client                         *PermissionClient
	protection                     *WorkerConfigurationProtection
	name, uid, installation, epoch string
}

var _ evidence.WorkerConfigurationReader = (*WorkerConfigurationSource)(nil)

// NewWorkerConfigurationSource reads the profile ConfigMap name (UID uid, as
// read by name at startup). installation and epoch are the IDs Secret's
// installationID and issuerEpoch.
func NewWorkerConfigurationSource(client *PermissionClient, protection *WorkerConfigurationProtection, name, uid, installation, epoch string) (*WorkerConfigurationSource, error) {
	if client == nil || protection == nil || protection.configMapProtection == nil || protection.observer != client || protection.plan.SourceName != name || !installationRefValid(name, uid) || !value.UUID(uid) || !value.UUID(installation) || !value.UUID(epoch) {
		return nil, artifact.ErrInvalid
	}
	return &WorkerConfigurationSource{client, protection, name, uid, installation, epoch}, nil
}

func (s *WorkerConfigurationSource) snapshot(ctx context.Context) (value.DownloadWorkerConfiguration, error) {
	data, _, e := s.client.installationConfig(ctx, s.name, s.uid)
	if e != nil || len(data) != 1 {
		return value.DownloadWorkerConfiguration{}, artifact.ErrInvalid
	}
	return workerConfiguration(ctx, s.client, []byte(data["worker-profile.json"]), s.uid, s.installation, s.epoch)
}

// workerConfiguration resolves a v3 worker-profile.json document of the
// client's namespace. The generated IDs are the caller's; the namespace UID
// is the client's namespace reference; the service account, PriorityClass,
// control ConfigMap and store Secret UIDs are read by name. The revision
// digest covers the canonical document only.
func workerConfiguration(ctx context.Context, client *PermissionClient, raw []byte, sourceUID, installation, epoch string) (value.DownloadWorkerConfiguration, error) {
	var zero value.DownloadWorkerConfiguration
	var w contracts.WorkerConfiguration
	if len(raw) == 0 || len(raw) > 16384 {
		return zero, artifact.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil || d.Decode(&struct{}{}) != io.EOF || w.Format != contracts.WorkerConfigurationFormat || w.Namespace != client.control.Name || w.Revision < 1 || w.Revision > 2147483647 || w.MaxRuntimeSeconds < 30 || w.MaxRuntimeSeconds > 28800 || w.ImagePullSecrets == nil || len(w.ImagePullSecrets) > 4 {
		return zero, artifact.ErrInvalid
	}
	names := append([]string{w.ServiceAccount, w.PriorityClass, w.ControlConfig}, w.ImagePullSecrets...)
	if w.StoreCredentials != "" {
		names = append(names, w.StoreCredentials)
	}
	for _, name := range names {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return zero, artifact.ErrInvalid
		}
	}
	canonical := jsontext.Value(bytes.Clone(raw))
	if canonical.Canonicalize() != nil {
		return zero, artifact.ErrInvalid
	}
	ns := "/api/v1/namespaces/" + w.Namespace
	p := value.DownloadWorkerProfile{Configuration: identity.Revision{UID: sourceUID, Generation: w.Revision, Digest: sha256.Sum256(canonical)}, InstallationID: installation, ClusterID: client.clusterID, Namespace: w.Namespace, NamespaceUID: client.control.UID, ServiceAccount: w.ServiceAccount, PriorityClass: w.PriorityClass, ControlConfig: w.ControlConfig, Image: w.Image, CPUMillis: w.CPUMillis, MemoryBytes: w.MemoryBytes, MaxRuntime: time.Duration(w.MaxRuntimeSeconds) * time.Second, StoreCredentialSecret: w.StoreCredentials}
	copy(p.ImagePullSecrets[:], w.ImagePullSecrets)
	type ref struct {
		path string
		uid  *string
	}
	refs := []ref{{ns + "/serviceaccounts/" + p.ServiceAccount, &p.ServiceAccountUID}, {"/apis/scheduling.k8s.io/v1/priorityclasses/" + p.PriorityClass, &p.PriorityClassUID}, {ns + "/configmaps/" + p.ControlConfig, &p.ControlConfigUID}}
	if p.StoreCredentialSecret != "" {
		refs = append(refs, ref{ns + "/secrets/" + p.StoreCredentialSecret, &p.StoreCredentialSecretUID})
	}
	for _, v := range refs {
		uid, e := ObjectUIDFrom(ctx, client, v.path)
		if e != nil {
			return zero, artifact.ErrDownloadUnavailable
		}
		*v.uid = uid
	}
	out := value.DownloadWorkerConfiguration{Profile: p, RecoveryEpoch: epoch, Suspended: w.Suspended}
	if !p.Valid() || !value.UUID(epoch) {
		return zero, artifact.ErrInvalid
	}
	return out, nil
}

func (s *WorkerConfigurationSource) ReadWorkerConfiguration(ctx context.Context) (value.DownloadWorkerObservation, error) {
	var out value.DownloadWorkerObservation
	if s == nil || ctx == nil {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	started := s.client.now()
	c, e := s.snapshot(ctx)
	if e != nil {
		return out, e
	}
	c.ProtectionDigest = s.protection.digest
	out = value.DownloadWorkerObservation{Configuration: c, ObservedAt: started, FreshUntil: started.Add(5 * time.Second)}
	if !out.Valid(s.client.now()) || ctx.Err() != nil {
		return value.DownloadWorkerObservation{}, artifact.ErrDownloadExpired
	}
	return out, nil
}
