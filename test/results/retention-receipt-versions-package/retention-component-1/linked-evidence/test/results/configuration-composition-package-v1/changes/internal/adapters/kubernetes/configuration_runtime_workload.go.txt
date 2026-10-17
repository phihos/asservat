package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// BuildProvisionedHubWorkerWorkload reuses the existing inert Restricted
// workload and its exact API permissions, but mounts the three SQL credentials
// only from the producer's immutable installation-derived projection. The
// separately supplied provider Secret carries only storage and audit-key
// credentials; it cannot substitute SQL role material or its receipt manifest.
// No object is applied, no replica is started and no source is accepted here.
func BuildProvisionedHubWorkerWorkload(p HubWorkerWorkloadPlan, installationID string) (*HubWorkerWorkload, error) {
	if !authorization.UUID(installationID) {
		return nil, cfg.ErrInvalid
	}
	projection := "asservat-configuration-runtime-" + strings.ReplaceAll(installationID, "-", "")
	if p.Credentials == projection {
		return nil, cfg.ErrInvalid
	}
	w, err := BuildHubWorkerWorkload(p)
	if err != nil {
		return nil, err
	}
	sources := w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources
	// These positions and keys come from the fixed builder above, not a
	// caller-supplied Pod or unbounded projection list.
	sources[1].Secret.Items = []core.KeyToPath{
		{Key: "audit-storage.json", Path: "audit-storage.json"},
		{Key: "audit-wrap.token", Path: "audit-wrap.token"},
		{Key: "audit-unwrap.token", Path: "audit-unwrap.token"},
	}
	items := []core.KeyToPath{{Key: contracts.ConfigurationRuntimeRoleManifestFile, Path: contracts.ConfigurationRuntimeRoleManifestFile}}
	for _, path := range []string{"sql-fleet.json", "sql-configuration.json", "sql-audit.json"} {
		items = append(items, core.KeyToPath{Key: path, Path: path})
	}
	w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources = append(sources, core.VolumeProjection{Secret: &core.SecretProjection{
		LocalObjectReference: core.LocalObjectReference{Name: projection}, Items: items, Optional: ptr.To(false),
	}})
	return w, nil
}
