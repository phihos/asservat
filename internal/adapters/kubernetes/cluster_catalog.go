package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
)

const clusterCatalogDenial = "Asservat cluster catalog administrator is required."

// ClusterCatalogProtection guards the ADR-185 cluster catalog ConfigMap.
type ClusterCatalogProtection struct{ *configMapProtection }

func ClusterCatalogAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-cluster-catalog", clusterCatalogDenial)
}
func NewClusterCatalogProtection(observer, probe *PermissionClient, plan cfg.ConfigMapAdministration, pin GuardPin) (*ClusterCatalogProtection, error) {
	g, err := newConfigMapProtection(observer, probe, plan, pin, "protected-cluster-catalog", clusterCatalogDenial)
	if err != nil {
		return nil, err
	}
	return &ClusterCatalogProtection{g}, nil
}

// ClusterCatalogSource reads the guarded catalog. Its entries carry no
// authority; the hub-api checks each against SQL and the per-cluster guards.
type ClusterCatalogSource struct {
	client     *PermissionClient
	protection *ClusterCatalogProtection
	name, uid  string
}

func NewClusterCatalogSource(client *PermissionClient, protection *ClusterCatalogProtection, name, uid string) (*ClusterCatalogSource, error) {
	if client == nil || protection == nil || protection.configMapProtection == nil || protection.observer != client || protection.plan.SourceName != name || !installationRefValid(name, uid) || !value.UUID(uid) {
		return nil, artifact.ErrInvalid
	}
	return &ClusterCatalogSource{client, protection, name, uid}, nil
}

func (s *ClusterCatalogSource) snapshot(ctx context.Context) ([]byte, contracts.OwnerClusterCatalog, error) {
	var out contracts.OwnerClusterCatalog
	data, _, e := s.client.installationConfig(ctx, s.name, s.uid)
	raw := []byte(data[contracts.OwnerClusterCatalogFile])
	if e != nil || len(data) != 1 || len(raw) == 0 || len(raw) > contracts.OwnerClusterCatalogMaxBytes {
		return nil, out, artifact.ErrInvalid
	}
	out, e = contracts.DecodeOwnerClusterCatalog(bytes.NewReader(raw))
	if e != nil || out.Format != contracts.OwnerClusterCatalogFormat || out.Clusters == nil || len(out.Clusters) > contracts.OwnerClusterCatalogSlots {
		return nil, contracts.OwnerClusterCatalog{}, artifact.ErrInvalid
	}
	encoded, e := json.Marshal(out)
	a, z := jsontext.Value(bytes.Clone(raw)), jsontext.Value(encoded)
	if e != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) {
		return nil, contracts.OwnerClusterCatalog{}, artifact.ErrInvalid
	}
	return a, out, nil
}

// ReadClusterCatalog reads the catalog twice between current guard proofs.
func (s *ClusterCatalogSource) ReadClusterCatalog(ctx context.Context) (contracts.OwnerClusterCatalog, error) {
	var zero contracts.OwnerClusterCatalog
	if s == nil || ctx == nil {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if _, _, e := s.protection.current(ctx); e != nil {
		return zero, e
	}
	first, out, e := s.snapshot(ctx)
	if e != nil {
		return zero, e
	}
	again, _, e := s.snapshot(ctx)
	if e != nil || !bytes.Equal(first, again) {
		return zero, artifact.ErrIntegrity
	}
	last, e := checkAdmissionGuard(ctx, s.client, s.protection.plan.Name, s.protection.pin, s.protection.policy, s.protection.binding)
	if e != nil || last == "" || ctx.Err() != nil {
		return zero, artifact.ErrInvalid
	}
	return out, nil
}
