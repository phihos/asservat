package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// ClusterJoinPlan is one regional slot's hub-side join (ADR-196 decision 1):
// the capability and work-trust sources with their guards, the immutable
// retention topology and the catalog entry they complete.
type ClusterJoinPlan struct {
	Control      cfg.NamespaceRef
	Installation string
	// Slot 0 derives it from the catalog: the cluster's existing position on
	// an exact rerun, otherwise the next free slot.
	Slot int
	Admins       []cfg.KubernetesActor
	Catalog      contracts.WorkerObjectReference
	Topology     contracts.RetentionTopologySettings
	// Entry carries the cluster, connector, executor, limits, capability
	// settings and trust; the join fills its source references and pin.
	Entry contracts.OwnerPublicCluster
	// Downloads, when set, adds the slot's derived download path after the
	// catalog entry (ADR-204 decision 4).
	Downloads *ClusterJoinDownloads
}

// ClusterJoinDownloads is the slot's derived download path and the guarded
// download environment sources it joins: the hub-api's, pinned by UID in the
// owner input, and, with regional capacity, the capacity processing source,
// which only its fixed name identifies (empty UID).
type ClusterJoinDownloads struct {
	RootID  string
	Path    contracts.DownloadEnvironmentPath
	Sources []contracts.WorkerObjectReference
}

// OwnerInputs reads the installed owner deployment input, the hub's record of
// its namespace, catalog pins and administrators.
func OwnerInputs(ctx context.Context, config *rest.Config, namespace, installation string) (contracts.OwnerDeployment, error) {
	var out contracts.OwnerDeployment
	api, err := installerAPI(config)
	if err != nil || ctx == nil || namespace == "" || !authorization.UUID(installation) {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	names := runtimeResourceNames(installation)
	cm, err := api.CoreV1().ConfigMaps(namespace).Get(call, names.OwnerInputs, meta.GetOptions{})
	if err != nil || len(cm.Data) != 1 {
		return out, cfg.ErrUnavailable
	}
	if out, err = contracts.DecodeOwnerDeployment(strings.NewReader(cm.Data["deployment.json"])); err != nil || out.InstallationID != installation || out.Public == nil {
		return contracts.OwnerDeployment{}, cfg.ErrInvalid
	}
	return out, nil
}

// ReadRegionalOffer reads the hub's published regional offer.
func ReadRegionalOffer(ctx context.Context, config *rest.Config, namespace, installation string) (contracts.RegionalOffer, error) {
	var out contracts.RegionalOffer
	api, err := installerAPI(config)
	if err != nil || ctx == nil || namespace == "" || !authorization.UUID(installation) {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	cm, err := api.CoreV1().ConfigMaps(namespace).Get(call, contracts.RegionalOfferName(installation), meta.GetOptions{})
	if err != nil || len(cm.Data) != 1 {
		return out, cfg.ErrUnavailable
	}
	if strictGuardJSON([]byte(cm.Data[contracts.RegionalOfferFile]), &out) != nil || out.Format != contracts.RegionalOfferFormat || out.InstallationID != installation {
		return contracts.RegionalOffer{}, cfg.ErrInvalid
	}
	return out, nil
}

// JoinRegionalCluster creates the slot's guarded capability and work-trust
// sources and its topology, create-only with exact reopen, then appends the
// entry to the guarded catalog by resourceVersion CAS. The catalog write
// makes the hub-api restart its process to read the new entry; only the
// optional download path additions follow it.
func JoinRegionalCluster(ctx context.Context, config *rest.Config, p ClusterJoinPlan) (contracts.OwnerPublicCluster, error) {
	e := p.Entry
	if ctx == nil || config == nil || p.Slot < 0 || p.Slot > contracts.OwnerClusterCatalogSlots || len(p.Admins) == 0 || !authorization.UUID(p.Control.UID) || !authorization.UUID(p.Catalog.UID) || !authorization.UUID(e.ClusterID) || p.Topology.TargetClusterID != e.ClusterID {
		return e, cfg.ErrInvalid
	}
	if d := p.Downloads; d != nil {
		if !authorization.UUID(d.RootID) || !authorization.UUID(d.Path.ID) || d.Path.TargetClusterID != e.ClusterID || len(d.Sources) < 1 || len(d.Sources) > 2 {
			return e, cfg.ErrInvalid
		}
		for i, s := range d.Sources {
			if s.Name == "" || (s.UID != "" && !authorization.UUID(s.UID)) || slices.ContainsFunc(d.Sources[:i], func(v contracts.WorkerObjectReference) bool { return v.Name == s.Name }) {
				return e, cfg.ErrInvalid
			}
		}
	}
	api, err := installerAPI(config)
	if err != nil {
		return e, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, time.Minute)
	defer end()
	if p.Slot == 0 {
		if p.Slot, err = catalogSlot(call, api, p, e.ClusterID); err != nil {
			return e, err
		}
	}
	capability, err := json.Marshal(e.Settings)
	if err != nil {
		return e, cfg.ErrInvalid
	}
	trust, err := contracts.EncodeAPIContextTrust(e.Trust)
	if err != nil {
		return e, cfg.ErrInvalid
	}
	name := func(kind string) string { return contracts.OwnerClusterSourceName(p.Installation, p.Slot, kind) }
	if e.Capability, err = ensureGuardedSource(call, api, p, name("capability"), "context-capability.json", capability, ContextCapabilityAdmission); err != nil {
		return e, err
	}
	if e.WorkTrust, err = ensureGuardedSource(call, api, p, name("work-trust"), "api-context-work-trust.json", trust, APIContextWorkTrustAdmission); err != nil {
		return e, err
	}
	topology, err := json.Marshal(p.Topology)
	if err != nil {
		return e, cfg.ErrInvalid
	}
	canonical := jsontext.Value(append([]byte(nil), topology...))
	if canonical.Canonicalize() != nil {
		return e, cfg.ErrInvalid
	}
	object, err := ensureImmutableData(call, api, p.Control.Name, name("topology"), "topology.json", topology)
	if err != nil {
		return e, err
	}
	sum := sha256.Sum256(canonical)
	e.Topology = contracts.OwnerNativeTopology{TargetClusterID: e.ClusterID, Name: object.Name, UID: object.UID, SHA256: hex.EncodeToString(sum[:])}
	if err = appendCatalogEntry(call, api, p, e); err != nil {
		return e, err
	}
	// The path follows the entry: a source path is accepted only once the
	// restarted hub-api derives it from the catalog, so the reverse order
	// would fail the current source closed until the restart.
	if d := p.Downloads; d != nil {
		for _, source := range d.Sources {
			if err = addDownloadPath(call, api, p.Control.Name, source, d.RootID, p.Installation, d.Path); err != nil {
				return e, err
			}
		}
	}
	return e, nil
}

// addDownloadPath adds one derived path to a guarded download environment
// source by resourceVersion CAS, as an administrator does: the path, its ID
// in every client's PathIDs and the next revision. Operators name no paths.
// A source already holding the equal path in every client is an exact rerun
// and is not written; another path with that ID refuses.
func addDownloadPath(ctx context.Context, api kubernetes.Interface, namespace string, source contracts.WorkerObjectReference, root, installation string, path contracts.DownloadEnvironmentPath) error {
	configMaps := api.CoreV1().ConfigMaps(namespace)
	for range 3 {
		c, err := configMaps.Get(ctx, source.Name, meta.GetOptions{})
		if err != nil || !authorization.UUID(string(c.UID)) || (source.UID != "" && string(c.UID) != source.UID) || len(c.Data) != 1 {
			return cfg.ErrUnavailable
		}
		var s contracts.DownloadEnvironmentSettings
		if strictGuardJSON([]byte(c.Data[contracts.DownloadEnvironmentFile]), &s) != nil || s.Format != contracts.DownloadEnvironmentFormat || s.RootID != root || s.InstallationID != installation || s.Paths == nil || s.Clients == nil {
			return cfg.ErrInvalid
		}
		changed := false
		switch i := slices.IndexFunc(s.Paths, func(v contracts.DownloadEnvironmentPath) bool { return v.ID == path.ID }); {
		case i >= 0 && s.Paths[i] != path:
			return cfg.ErrChanged
		case i < 0:
			if len(s.Paths) >= 32 {
				return cfg.ErrUnavailable
			}
			s.Paths, changed = append(s.Paths, path), true
		}
		for i := range s.Clients {
			if !slices.Contains(s.Clients[i].PathIDs, path.ID) {
				if len(s.Clients[i].PathIDs) >= 32 {
					return cfg.ErrUnavailable
				}
				s.Clients[i].PathIDs, changed = append(s.Clients[i].PathIDs, path.ID), true
			}
		}
		if !changed {
			return nil
		}
		if s.Revision < 1 || s.Revision >= 2147483647 {
			return cfg.ErrInvalid
		}
		s.Revision++
		raw, err := json.Marshal(s)
		if err != nil || len(raw) > contracts.DownloadEnvironmentMaxBytes {
			return cfg.ErrInvalid
		}
		c.Data[contracts.DownloadEnvironmentFile] = string(raw)
		if _, err = configMaps.Update(ctx, c, meta.UpdateOptions{}); err == nil {
			return nil
		} else if !apierrors.IsConflict(err) {
			return cfg.ErrUnavailable
		}
	}
	return cfg.ErrUnavailable
}

func ensureGuardedSource(ctx context.Context, api kubernetes.Interface, p ClusterJoinPlan, name, key string, data []byte, build func(cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error)) (contracts.OwnerPublicGuardedSource, error) {
	var out contracts.OwnerPublicGuardedSource
	// The guard exists before its source, as for every public source.
	policy, binding, err := build(cfg.ConfigMapAdministration{Name: name + "-guard", SourceName: name, ControlNamespace: p.Control, Administrators: p.Admins})
	if err != nil {
		return out, err
	}
	if out.Guard, err = ensureAdmissionGuard(ctx, api, policy, binding, p.Admins); err != nil {
		return out, err
	}
	if out.Source, err = ensureImmutableData(ctx, api, p.Control.Name, name, key, data); err != nil {
		return out, err
	}
	return out, nil
}

// ensureImmutableData creates one immutable single-key ConfigMap, or reopens
// it only when its data is exactly the same.
func ensureImmutableData(ctx context.Context, api kubernetes.Interface, namespace, name, key string, data []byte) (contracts.WorkerObjectReference, error) {
	configMaps := api.CoreV1().ConfigMaps(namespace)
	c, err := configMaps.Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Data: map[string]string{key: string(data)}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if c, err = configMaps.Get(ctx, name, meta.GetOptions{}); err == nil && (c.Immutable == nil || !*c.Immutable || len(c.Data) != 1 || c.Data[key] != string(data)) {
			return contracts.WorkerObjectReference{}, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(c.UID)) {
		return contracts.WorkerObjectReference{}, cfg.ErrUnavailable
	}
	return contracts.WorkerObjectReference{Name: c.Name, UID: string(c.UID)}, nil
}

// catalogSlot is the cluster's 1-based catalog position, or the next free
// slot when the catalog does not name it yet.
func catalogSlot(ctx context.Context, api kubernetes.Interface, p ClusterJoinPlan, cluster string) (int, error) {
	c, err := api.CoreV1().ConfigMaps(p.Control.Name).Get(ctx, p.Catalog.Name, meta.GetOptions{})
	if err != nil || string(c.UID) != p.Catalog.UID || len(c.Data) != 1 {
		return 0, cfg.ErrUnavailable
	}
	catalog, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(c.Data[contracts.OwnerClusterCatalogFile]))
	if err != nil || catalog.Format != contracts.OwnerClusterCatalogFormat || catalog.Clusters == nil {
		return 0, cfg.ErrInvalid
	}
	if i := slices.IndexFunc(catalog.Clusters, func(v contracts.OwnerPublicCluster) bool { return v.ClusterID == cluster }); i >= 0 {
		return i + 1, nil
	}
	if len(catalog.Clusters) >= contracts.OwnerClusterCatalogSlots {
		return 0, cfg.ErrUnavailable
	}
	return len(catalog.Clusters) + 1, nil
}

// appendCatalogEntry adds the slot's entry by resourceVersion CAS. An equal
// entry for the cluster is an exact rerun; any other entry for it, or a full
// catalog, refuses.
func appendCatalogEntry(ctx context.Context, api kubernetes.Interface, p ClusterJoinPlan, e contracts.OwnerPublicCluster) error {
	configMaps := api.CoreV1().ConfigMaps(p.Control.Name)
	for range 3 {
		c, err := configMaps.Get(ctx, p.Catalog.Name, meta.GetOptions{})
		if err != nil || string(c.UID) != p.Catalog.UID || len(c.Data) != 1 {
			return cfg.ErrUnavailable
		}
		catalog, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(c.Data[contracts.OwnerClusterCatalogFile]))
		if err != nil || catalog.Format != contracts.OwnerClusterCatalogFormat || catalog.Clusters == nil {
			return cfg.ErrInvalid
		}
		for _, v := range catalog.Clusters {
			if v.ClusterID == e.ClusterID {
				if !equalJSON(v, e) {
					return cfg.ErrChanged
				}
				return nil
			}
		}
		if len(catalog.Clusters) >= contracts.OwnerClusterCatalogSlots || len(catalog.Clusters) != p.Slot-1 {
			return cfg.ErrUnavailable
		}
		catalog.Clusters = append(catalog.Clusters, e)
		raw, err := json.Marshal(catalog)
		if err != nil || len(raw) > contracts.OwnerClusterCatalogMaxBytes {
			return cfg.ErrInvalid
		}
		c.Data[contracts.OwnerClusterCatalogFile] = string(raw)
		if _, err = configMaps.Update(ctx, c, meta.UpdateOptions{}); err == nil {
			return nil
		} else if !apierrors.IsConflict(err) {
			return cfg.ErrUnavailable
		}
	}
	return cfg.ErrUnavailable
}
