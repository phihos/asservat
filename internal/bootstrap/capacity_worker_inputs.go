package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/netip"
	"os"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"k8s.io/apimachinery/pkg/util/validation"
)

func capacityRuntimeReference(v contracts.WorkerObjectReference) bool {
	return authorization.UUID(v.UID) && len(validation.IsDNS1123Subdomain(v.Name)) == 0
}
func capacityRuntimeGuard(g contracts.OwnerDeploymentGuard) bool {
	if len(validation.IsDNS1123Label(g.Name)) != 0 || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) ||
		!identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || g.PolicyGeneration > 2147483647 || len(g.Administrators) < 1 || len(g.Administrators) > 32 {
		return false
	}
	seen := map[contracts.OwnerDeploymentActor]bool{}
	for _, a := range g.Administrators {
		if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) || seen[a] {
			return false
		}
		seen[a] = true
	}
	return true
}
func capacityRuntimeEndpoint(p contracts.OwnerProviderEndpoint) bool {
	if !ownerEndpoint(p.Endpoint) {
		return false
	}
	_, _, err := mtls.OwnerTrustRoots(p.Roots, time.Now())
	return err == nil
}

func capacityRuntimeQualification(raw []byte) (app.CapacityQualification, error) {
	var out app.CapacityQualification
	if len(raw) < 2 || len(raw) > 128<<10 {
		return out, mounts.ErrUnavailable
	}
	a := jsontext.Value(bytes.Clone(raw))
	if a.Canonicalize() != nil {
		return out, mounts.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return app.CapacityQualification{}, mounts.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !out.Valid() || !app.ValidateRootBackingInput(out.RootBacking) {
		return app.CapacityQualification{}, mounts.ErrUnavailable
	}
	b, err := json.Marshal(out)
	z := jsontext.Value(b)
	if err != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) {
		return app.CapacityQualification{}, mounts.ErrUnavailable
	}
	return out, nil
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

// regionalTargets are the capacity hub-worker's: its regional qualifications.
func regionalTargets(r []app.CapacityNamespaceQualification) []string {
	out := make([]string, len(r))
	for i, v := range r {
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

func readCapacityWorkerInputs(ctx context.Context, files *os.Root) (contracts.CapacityDeployment, contracts.CapacityCredentialManifest, app.CapacityQualification, error) {
	var c contracts.CapacityDeployment
	var m contracts.CapacityCredentialManifest
	var q app.CapacityQualification
	fail := func() (contracts.CapacityDeployment, contracts.CapacityCredentialManifest, app.CapacityQualification, error) {
		return contracts.CapacityDeployment{}, contracts.CapacityCredentialManifest{}, app.CapacityQualification{}, mounts.ErrUnavailable
	}
	b, err := mounts.Read(ctx, files, contracts.CapacityDeploymentFile, contracts.CapacityDeploymentMaxBytes)
	if err != nil {
		return fail()
	}
	c, err = contracts.DecodeCapacityDeployment(bytes.NewReader(b))
	clear(b)
	if err != nil || c.Format != contracts.CapacityDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.PermissionRootID) ||
		!authorization.UUID(c.RoleRootUID) || !authorization.UUID(c.RoleSetupID) || c.AccountVersion != c.RoleSetupID+"-account/v1" {
		return fail()
	}
	q, err = capacityRuntimeQualification(c.Qualification)
	if err != nil || q.RootBacking.RootID != c.PermissionRootID || q.RootBacking.InstallationID != c.InstallationID || q.RootBacking.AccountVersion != c.AccountVersion {
		return fail()
	}
	control := c.Control
	if !authorization.UUID(control.ClusterID) || !capacityRuntimeReference(control.Namespace) || len(validation.IsDNS1123Label(control.Namespace.Name)) != 0 ||
		!capacityRuntimeEndpoint(control.Kubernetes) || !capacityRuntimeGuard(control.Guard) || !capacityRuntimeReference(control.ProbeAccount) ||
		control.StatusUsers == nil || !identity.Strings(control.StatusUsers, 16, 256) || len(c.Clusters) != len(q.NamespaceGuards) {
		return fail()
	}
	seen := map[string]bool{}
	for _, v := range c.Clusters {
		if !authorization.UUID(v.ClusterID) || seen[v.ClusterID] || !capacityRuntimeReference(v.ProbeNamespace) || len(validation.IsDNS1123Label(v.ProbeNamespace.Name)) != 0 ||
			!capacityRuntimeReference(v.ProbeAccount) || !capacityClusterEndpoint(c.LocalOwner != nil, control.ClusterID, v.ClusterID, v.Kubernetes) || !capacityRuntimeGuard(v.Guard) || !slices.IsSorted(v.Keys) {
			return fail()
		}
		seen[v.ClusterID] = true
		found := false
		for _, pin := range q.NamespaceGuards {
			if pin.ClusterID == v.ClusterID && slices.Equal(pin.Keys, v.Keys) {
				found = true
			}
		}
		if !found {
			return fail()
		}
	}
	if !capacityRuntimeReference(c.Processing.Source) || c.Processing.Source.UID != q.RootBacking.ProcessingSourceUID || !capacityRuntimeGuard(c.Processing.Guard) ||
		c.Processing.Guard.Name == control.Guard.Name {
		return fail()
	}
	// The regional targets are read at start; the template is checked here.
	if _, err = downloadEnvironmentPaths(c.InstallationID, control.ClusterID, c.Processing.Paths, c.Processing.PathTemplate, nil); err != nil {
		return fail()
	}
	p := c.Postgres
	if p.MaxConnections != 1 || p.Port < 1 || p.Port > 65535 || !identity.Text(p.Database, 63) {
		return fail()
	}
	if _, err = netip.ParseAddr(p.Host); err != nil && !ownerDNSName.MatchString(p.Host) {
		return fail()
	}
	if _, _, err = mtls.OwnerTrustRoots(p.Roots, time.Now()); err != nil {
		return fail()
	}
	b, err = mounts.Read(ctx, files, contracts.CapacityCredentialManifestFile, contracts.CapacityCredentialManifestMaxBytes)
	if err != nil {
		return fail()
	}
	m, err = contracts.DecodeCapacityCredentialManifest(bytes.NewReader(b))
	clear(b)
	if err != nil || postgres.ValidateCapacityCredentialManifest(m, time.Now()) != nil || m.Input.InstallationID != c.InstallationID ||
		m.RootUID != c.RoleRootUID || m.SetupID != c.RoleSetupID || m.Capacity.PermissionRootID != c.PermissionRootID || ctx.Err() != nil {
		return fail()
	}
	return c, m, q, nil
}

// Installed observation uses the authenticated local hop only. An endpoint in
// that profile is rejected rather than ignored or used as a remote fallback.
// Without the installed local owner this process reads a cluster API directly,
// which outbound-only connectivity permits only for the hub's own cluster
// (ADR-179).
func capacityClusterEndpoint(installed bool, hub, cluster string, endpoint contracts.OwnerProviderEndpoint) bool {
	if installed {
		return endpoint.Endpoint == "" && len(endpoint.Roots) == 0
	}
	return cluster == hub && capacityRuntimeEndpoint(endpoint)
}
