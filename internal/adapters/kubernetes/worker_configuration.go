package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ErrWorkerUnconfigured is a protected source holding exactly the installed
// unconfigured document (ADR-194 D1): the process serves no downloads.
var ErrWorkerUnconfigured = errors.New("worker configuration unconfigured")

type WorkerConfigurationSource struct {
	client                  *PermissionClient
	protection              *WorkerConfigurationProtection
	name, uid, installation string
}

var _ evidence.WorkerConfigurationReader = (*WorkerConfigurationSource)(nil)

func NewWorkerConfigurationSource(client *PermissionClient, protection *WorkerConfigurationProtection, name, uid, installation string) (*WorkerConfigurationSource, error) {
	if client == nil || protection == nil || protection.configMapProtection == nil || protection.observer != client || protection.plan.SourceName != name || !installationRefValid(name, uid) || !value.UUID(uid) || !value.UUID(installation) {
		return nil, artifact.ErrInvalid
	}
	return &WorkerConfigurationSource{client, protection, name, uid, installation}, nil
}
func (s *WorkerConfigurationSource) snapshot(ctx context.Context) (value.DownloadWorkerConfiguration, error) {
	var out value.DownloadWorkerConfiguration
	data, _, e := s.client.installationConfig(ctx, s.name, s.uid)
	if e == nil && len(data) == 1 && data["worker-profile.json"] == contracts.UnconfiguredWorkerConfiguration(s.installation) {
		return out, ErrWorkerUnconfigured
	}
	if e != nil || len(data) != 1 || len(data["worker-profile.json"]) == 0 || len(data["worker-profile.json"]) > 16384 {
		return out, artifact.ErrInvalid
	}
	b := []byte(data["worker-profile.json"])
	var w contracts.WorkerConfiguration
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return out, artifact.ErrInvalid
	}
	encoded, e := json.Marshal(w)
	a, z := jsontext.Value(b), jsontext.Value(encoded)
	if e != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || !(w.Format == "asservat-worker-configuration/v1" && w.StoreCredentials == nil || w.Format == "asservat-worker-configuration/v2" && w.StoreCredentials != nil) || w.InstallationID != s.installation || w.ClusterID != s.client.clusterID || w.Namespace.Name != s.client.control.Name || w.Namespace.UID != s.client.control.UID || w.Revision < 1 || w.Revision > 2147483647 || w.MaxRuntimeSeconds < 30 || w.MaxRuntimeSeconds > 28800 || w.ImagePullSecrets == nil || len(w.ImagePullSecrets) > 4 {
		return out, artifact.ErrInvalid
	}
	h, e := hex.DecodeString(w.ControlConfig.SHA256)
	if e != nil || len(h) != 32 || hex.EncodeToString(h) != w.ControlConfig.SHA256 {
		return out, artifact.ErrInvalid
	}
	p := value.DownloadWorkerProfile{Configuration: identity.Revision{UID: s.uid, Generation: w.Revision, Digest: sha256.Sum256(a)}, InstallationID: w.InstallationID, ClusterID: w.ClusterID, Namespace: w.Namespace.Name, NamespaceUID: w.Namespace.UID, ServiceAccount: w.ServiceAccount.Name, ServiceAccountUID: w.ServiceAccount.UID, PriorityClass: w.PriorityClass.Name, PriorityClassUID: w.PriorityClass.UID, ControlConfig: w.ControlConfig.Name, ControlConfigUID: w.ControlConfig.UID, Image: w.Image, CPUMillis: w.CPUMillis, MemoryBytes: w.MemoryBytes, MaxRuntime: time.Duration(w.MaxRuntimeSeconds) * time.Second}
	copy(p.ControlDigest[:], h)
	if w.StoreCredentials != nil {
		p.StoreCredentialSecret, p.StoreCredentialSecretUID = w.StoreCredentials.Name, w.StoreCredentials.UID
		if len(validation.IsDNS1123Subdomain(p.StoreCredentialSecret)) != 0 || !value.UUID(p.StoreCredentialSecretUID) {
			return out, artifact.ErrInvalid
		}
	}
	copy(p.ImagePullSecrets[:], w.ImagePullSecrets)
	for _, name := range []string{p.ServiceAccount, p.PriorityClass, p.ControlConfig} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return out, artifact.ErrInvalid
		}
	}
	for _, name := range w.ImagePullSecrets {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return out, artifact.ErrInvalid
		}
	}
	out = value.DownloadWorkerConfiguration{Profile: p, RecoveryEpoch: w.RecoveryEpoch, Suspended: w.Suspended}
	if !p.Valid() || !value.UUID(w.RecoveryEpoch) {
		return value.DownloadWorkerConfiguration{}, artifact.ErrInvalid
	}
	if e = checkWorkerStoreSecret(ctx, s.client, p); e != nil {
		return value.DownloadWorkerConfiguration{}, e
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
	protection, until, e := s.protection.current(ctx)
	if e != nil {
		return out, e
	}
	c, e := s.snapshot(ctx)
	if e != nil {
		return out, e
	}
	again, e := s.snapshot(ctx)
	if e != nil || again != c {
		return out, artifact.ErrIntegrity
	}
	last, e := checkAdmissionGuard(ctx, s.client, s.protection.plan.Name, s.protection.pin, s.protection.policy, s.protection.binding)
	if e != nil || last == "" {
		return out, artifact.ErrInvalid
	}
	c.ProtectionDigest = protection
	out = value.DownloadWorkerObservation{Configuration: c, ObservedAt: started, FreshUntil: identity.Earlier(started.Add(5*time.Second), until)}
	if !out.Valid(s.client.now()) || ctx.Err() != nil {
		return value.DownloadWorkerObservation{}, artifact.ErrDownloadExpired
	}
	return out, nil
}
