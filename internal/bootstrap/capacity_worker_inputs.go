package bootstrap

import (
	"encoding/hex"
	"slices"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"k8s.io/apimachinery/pkg/util/validation"
)

func capacityRuntimeReference(v contracts.WorkerObjectReference) bool {
	return authorization.UUID(v.UID) && len(validation.IsDNS1123Subdomain(v.Name)) == 0
}

func downloadPathRevision(v contracts.DownloadEnvironmentRevision) (identity.Revision, error) {
	out := identity.Revision{UID: v.UID, Generation: v.Generation}
	b, err := hex.DecodeString(v.SHA256)
	if err != nil || len(b) != len(out.Digest) || hex.EncodeToString(b) != v.SHA256 {
		return out, mounts.ErrUnavailable
	}
	copy(out.Digest[:], b)
	if !out.Valid() {
		return out, mounts.ErrUnavailable
	}
	return out, nil
}

// downloadPathTemplate checks every field a derived path takes from the
// template (ADR-204 decision 4). The hub is the acquisition, connector and
// hub cluster (decision 3), so those three regions are one.
func downloadPathTemplate(t contracts.DownloadEnvironmentPathTemplate, hub string) bool {
	_, worker := downloadPathRevision(t.WorkerConfiguration)
	_, configuration := downloadPathRevision(t.HubConfiguration)
	return worker == nil && configuration == nil && authorization.UUID(t.WorkerConfiguration.UID) && authorization.UUID(t.HubConfiguration.UID) &&
		authorization.UUID(hub) && authorization.UUID(t.StoreID) && t.AcquisitionClusterID == hub && t.ConnectorClusterID == hub && t.HubClusterID == hub &&
		identity.Text(t.StorageRegion, 63) && identity.Text(t.HubRegion, 63) && t.AcquisitionRegion == t.HubRegion && t.ConnectorRegion == t.HubRegion
}

// downloadEnvironmentPaths are the pinned paths plus, with a template, one
// path derived for each target cluster (ADR-204 decision 4). The hub-api
// passes its guarded catalog's clusters and the capacity hub-worker its
// regional qualifications, so both derive the same paths. An invalid
// template, a repeated target or a repeated path ID refuses; without a
// template the targets are not used.
func downloadEnvironmentPaths(installation, hub string, pinned []contracts.DownloadEnvironmentPath, template *contracts.DownloadEnvironmentPathTemplate, targets []string) ([]privacy.DownloadPath, error) {
	if template == nil || pinned == nil {
		return capacityRuntimeProcessingPaths(pinned)
	}
	if !authorization.UUID(installation) || !downloadPathTemplate(*template, hub) || len(targets) > 32 {
		return nil, mounts.ErrUnavailable
	}
	all := slices.Clone(pinned)
	seen := map[string]bool{}
	for _, target := range targets {
		if !authorization.UUID(target) || seen[target] {
			return nil, mounts.ErrUnavailable
		}
		seen[target] = true
		all = append(all, contracts.DownloadPathFor(installation, *template, target))
	}
	return capacityRuntimeProcessingPaths(all)
}

// catalogTargets are the hub-api's derived path targets: the clusters of the
// guarded catalog read at start.
func catalogTargets(c contracts.OwnerClusterCatalog) []string {
	out := make([]string, len(c.Clusters))
	for i, v := range c.Clusters {
		out[i] = v.ClusterID
	}
	return out
}

func capacityRuntimeProcessingPaths(in []contracts.DownloadEnvironmentPath) ([]privacy.DownloadPath, error) {
	// ADR-192: an empty set is valid; pinned paths only narrow a source.
	if in == nil || len(in) > 32 {
		return nil, mounts.ErrUnavailable
	}
	seen := map[string]bool{}
	out := make([]privacy.DownloadPath, 0, len(in))
	for _, v := range in {
		worker, err := downloadPathRevision(v.WorkerConfiguration)
		if err != nil {
			return nil, err
		}
		hub, err := downloadPathRevision(v.HubConfiguration)
		if err != nil {
			return nil, err
		}
		p := privacy.DownloadPath{ID: v.ID, TargetClusterID: v.TargetClusterID, StoreID: v.StoreID, StorageRegion: v.StorageRegion,
			AcquisitionClusterID: v.AcquisitionClusterID, AcquisitionRegion: v.AcquisitionRegion, ConnectorClusterID: v.ConnectorClusterID, ConnectorRegion: v.ConnectorRegion,
			HubClusterID: v.HubClusterID, HubRegion: v.HubRegion, WorkerConfiguration: worker, HubConfiguration: hub}
		if !p.Valid() || seen[p.ID] {
			return nil, mounts.ErrUnavailable
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out, nil
}
