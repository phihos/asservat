package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// PublicSources are the hub-local guarded sources the continuation creates
// before the owner projection (ADR-185). The owner input pins these exact
// references; per-cluster sources are added with each regional cluster.
// WorkerConfiguration and DownloadEnvironment exist only for a promoted owner.
type PublicSources struct {
	BrowserRootID                            string
	BrowserSettings, IdentitySettings        contracts.WorkerObjectReference
	ClusterCatalog                           contracts.OwnerPublicGuardedSource
	WorkerConfiguration, DownloadEnvironment contracts.OwnerPublicGuardedSource
}

// EnsurePublicSources creates or reopens the browser and identity settings and
// the empty cluster catalog with its guard. Existing settings are kept as the
// administrator left them; an existing guard must match exactly. A non-nil
// environment (ADR-194) also creates the unconfigured worker configuration
// and the owner download environment, each with its guard. A non-nil worker
// is the guarded profile source in the download workers' own namespace
// (ADR-204 decision 2): it replaces the hub namespace's worker marker, which
// is then not created.
func EnsurePublicSources(ctx context.Context, config *rest.Config, control cfg.NamespaceRef, installation string, admins []cfg.KubernetesActor, browser contracts.BrowserSettings, identity contracts.IdentitySettings, environment *contracts.DownloadEnvironmentSettings, worker *contracts.OwnerPublicGuardedSource) (PublicSources, error) {
	var out PublicSources
	if ctx == nil || config == nil || control.Name == "" || !authorization.UUID(control.UID) || !authorization.UUID(installation) || len(admins) == 0 || !authorization.UUID(browser.RootID) {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	configMaps := api.CoreV1().ConfigMaps(control.Name)
	ensureRaw := func(name, key, body string) (*core.ConfigMap, error) {
		created, e := configMaps.Create(call, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Data: map[string]string{key: body}}, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			created, e = configMaps.Get(call, name, meta.GetOptions{})
		}
		if e != nil || created.Name != name || !authorization.UUID(string(created.UID)) || len(created.Data) != 1 || created.Data[key] == "" {
			return nil, cfg.ErrUnavailable
		}
		return created, nil
	}
	ensure := func(name, key string, value any) (*core.ConfigMap, error) {
		body, e := json.Marshal(value)
		if e != nil {
			return nil, cfg.ErrInvalid
		}
		return ensureRaw(name, key, string(body))
	}
	guarded := func(source *core.ConfigMap, guard string, build func(cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error)) (contracts.OwnerPublicGuardedSource, error) {
		var zero contracts.OwnerPublicGuardedSource
		policy, binding, e := build(cfg.ConfigMapAdministration{Name: guard, SourceName: source.Name, ControlNamespace: control, Administrators: admins})
		if e != nil {
			return zero, e
		}
		// A reopen compares after the server's defaults (the second call of a
		// promoted continuation reopens the catalog guard).
		g, e := ensureAdmissionGuard(call, api, policy, binding, admins)
		if e != nil {
			return zero, e
		}
		return contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: source.Name, UID: string(source.UID)}, Guard: g}, nil
	}
	b, err := ensure(contracts.OwnerBrowserSettingsName(installation), "browser.json", browser)
	if err != nil {
		return out, err
	}
	var kept contracts.BrowserSettings
	if json.Unmarshal([]byte(b.Data["browser.json"]), &kept) != nil || !authorization.UUID(kept.RootID) {
		return out, cfg.ErrChanged
	}
	i, err := ensure(contracts.OwnerIdentitySettingsName(installation), "identity.json", identity)
	if err != nil {
		return out, err
	}
	catalogName := contracts.OwnerClusterCatalogName(installation)
	c, err := ensure(catalogName, contracts.OwnerClusterCatalogFile, contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: []contracts.OwnerPublicCluster{}})
	if err != nil {
		return out, err
	}
	out = PublicSources{BrowserRootID: kept.RootID,
		BrowserSettings:  contracts.WorkerObjectReference{Name: b.Name, UID: string(b.UID)},
		IdentitySettings: contracts.WorkerObjectReference{Name: i.Name, UID: string(i.UID)}}
	if out.ClusterCatalog, err = guarded(c, catalogName+"-guard", ClusterCatalogAdmission); err != nil {
		return PublicSources{}, err
	}
	if environment == nil {
		return out, nil
	}
	// An administrator later replaces the marker with a worker-profile.json
	// and the environment with download paths; reopening keeps both.
	workerName, environmentName := contracts.OwnerWorkerConfigurationName(installation), contracts.OwnerDownloadEnvironmentName(installation)
	if worker != nil {
		if !installationRefValid(worker.Source.Name, worker.Source.UID) || !authorization.UUID(worker.Source.UID) || worker.Source.Name == workerName || worker.Guard.Name == "" || !authorization.UUID(worker.Guard.PolicyUID) || !authorization.UUID(worker.Guard.BindingUID) {
			return PublicSources{}, cfg.ErrInvalid
		}
		out.WorkerConfiguration = *worker
	} else {
		w, err := ensureRaw(workerName, "worker-profile.json", contracts.UnconfiguredWorkerConfiguration(installation))
		if err != nil {
			return PublicSources{}, err
		}
		if out.WorkerConfiguration, err = guarded(w, workerName+"-guard", WorkerConfigurationAdmission); err != nil {
			return PublicSources{}, err
		}
	}
	e, err := ensure(environmentName, contracts.DownloadEnvironmentFile, environment)
	if err != nil {
		return PublicSources{}, err
	}
	if out.DownloadEnvironment, err = guarded(e, environmentName+"-guard", DownloadEnvironmentAdmission); err != nil {
		return PublicSources{}, err
	}
	return out, nil
}
