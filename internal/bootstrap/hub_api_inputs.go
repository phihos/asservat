package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Helm-native hub-api inputs (docs/reviews/helm-native-field-map.md): the
// loader merges the rendered config.json (H), the <name>-ids Secret (S),
// UIDs read by name (N) and provider-produced public values (J) into the
// in-process owner composition input. No pin is compared; the values only
// key SQL rows and select provider objects.

// hubAPIIDs are the generated installation IDs.
type hubAPIIDs = contracts.InstallationIDs

// hubAPIInputError names the missing or invalid input; the name is fixed text.
type hubAPIInputError string

func (e hubAPIInputError) Error() string     { return "hub-api input " + string(e) }
func (e hubAPIInputError) FixedStep() string { return "input-" + string(e) }
func (e hubAPIInputError) Unwrap() error     { return mounts.ErrUnavailable }

func readHubAPIIDs(_ context.Context, root *os.Root) (hubAPIIDs, error) {
	v, err := contracts.ReadInstallationIDs(root)
	if err != nil {
		var key contracts.InstallationIDError
		errors.As(err, &key)
		return hubAPIIDs{}, hubAPIInputError("ids-" + string(key))
	}
	return v, nil
}

func readHubAPIConfig(ctx context.Context, root *os.Root) (contracts.HubAPIConfig, error) {
	b, err := mounts.Read(ctx, root, contracts.HubAPIConfigFile, contracts.HubAPIConfigMaxBytes)
	if err != nil {
		return contracts.HubAPIConfig{}, hubAPIInputError("config")
	}
	defer clear(b)
	c, err := contracts.DecodeHubAPIConfig(bytes.NewReader(b))
	if err != nil || c.Format != contracts.HubAPIConfigFormat {
		return contracts.HubAPIConfig{}, hubAPIInputError("config")
	}
	return c, nil
}

// hubAPIResolver performs the startup reads by name (N) and from providers
// (J). The production implementation uses the hub-api's own credentials.
type hubAPIResolver interface {
	NamespaceUID(ctx context.Context, name string) (string, error)
	ObjectUID(ctx context.Context, group, resource, namespace, name string) (string, error)
	PKIRoots(ctx context.Context, mount string) ([][]byte, error)
	SigningKey(ctx context.Context, role, mount, name string) (int, ed25519.PublicKey, error)
	CapacityPin(ctx context.Context, root, installation string) (postgres.CapacityQualificationPin, error)
}

// readCA reads one mounted PEM bundle as DER certificates.
func readCA(ctx context.Context, files *os.Root, name string, now time.Time) ([][]byte, error) {
	b, err := mounts.Read(ctx, files, name, 32<<10)
	if err != nil {
		return nil, hubAPIInputError("ca-" + name)
	}
	roots, err := providerconfig.TrustRootsPEM(b, now)
	if err != nil {
		return nil, hubAPIInputError("ca-" + name)
	}
	return roots, nil
}

// buildHubAPIDeployment merges the inputs. files is the credential root that
// also holds the CA files.
func buildHubAPIDeployment(ctx context.Context, files *os.Root, h contracts.HubAPIConfig, ids hubAPIIDs, r hubAPIResolver, now time.Time) (contracts.OwnerDeployment, error) {
	var zero contracts.OwnerDeployment
	if ctx == nil || files == nil || r == nil {
		return zero, mounts.ErrUnavailable
	}
	for _, v := range []struct{ name, value string }{{"name", h.Name}, {"namespace", h.Namespace}, {"openBao", h.OpenBao.Endpoint}, {"objectStore", h.ObjectStore.Endpoint}} {
		if v.value == "" {
			return zero, hubAPIInputError(v.name)
		}
	}
	cas := map[string][][]byte{}
	for _, name := range []string{contracts.HubAPIKubernetesCAFile, contracts.HubAPIPostgresCAFile, contracts.HubAPIAuditStoreCAFile, contracts.HubAPIKeyServiceCAFile} {
		roots, err := readCA(ctx, files, name, now)
		if err != nil {
			return zero, err
		}
		cas[name] = roots
	}
	namespaceUID, err := r.NamespaceUID(ctx, h.Namespace)
	if err != nil {
		return zero, hubAPIInputError("namespace-uid")
	}
	configMapUID := func(namespace, name, step string) (contracts.WorkerObjectReference, error) {
		uid, err := r.ObjectUID(ctx, "", "configmaps", namespace, name)
		if err != nil {
			return contracts.WorkerObjectReference{}, hubAPIInputError(step + "-uid")
		}
		return contracts.WorkerObjectReference{Name: name, UID: uid}, nil
	}
	self := contracts.HubAPIName(h.Name, "hub-api")
	owner, err := configMapUID(h.Namespace, contracts.HubAPIName(h.Name, "owner-source"), "owner-configuration")
	if err != nil {
		return zero, err
	}
	names := providerconfig.OpenBaoNamesFor(ids.InstallationID)
	kubernetes := contracts.OwnerProviderEndpoint{Endpoint: contracts.HubAPIKubernetesEndpoint, Roots: cas[contracts.HubAPIKubernetesCAFile]}
	c := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: ids.InstallationID, ClusterID: ids.ClusterID, PermissionRootID: ids.PermissionRootID,
		Namespace: contracts.WorkerObjectReference{Name: h.Namespace, UID: namespaceUID}, ConfigurationUID: owner.UID, Kubernetes: kubernetes,
		ConfigurationProbes: []contracts.OwnerConfigurationProbe{}, SchedulingLeases: []contracts.OwnerSchedulingLease{},
		Postgres:   contracts.OwnerPostgresEndpoint{Host: h.Postgres.Host, Port: h.Postgres.Port, Database: h.Postgres.Database, Roots: cas[contracts.HubAPIPostgresCAFile], MaxConnections: contracts.HubAPIPostgresConnections},
		AuditStore: contracts.OwnerAuditStore{Endpoint: h.ObjectStore.Endpoint, Roots: cas[contracts.HubAPIAuditStoreCAFile], Region: h.ObjectStore.Region, Bucket: h.ObjectStore.AuditBucket},
		KeyService: contracts.OwnerKeyService{Endpoint: h.OpenBao.Endpoint, Roots: cas[contracts.HubAPIKeyServiceCAFile], AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: names.AuditKey,
			PKIMount: contracts.SmallOpenBaoOwnerPKIMount, ServerRole: names.OwnerServerRole, ClientRole: names.OwnerClientRole},
		Connections: h.Connections, Concurrency: h.Concurrency}
	// The provider roles are "<name>-hub-api-<purpose>" (the ServiceAccount
	// name plus the purpose; providerconfig.OpenBaoRoleName).
	profile := contracts.OwnerProviderAuthentication{Format: contracts.OwnerProviderAuthenticationFormat, AuthMount: contracts.SmallOpenBaoOwnerAuthMount, ServiceAccount: contracts.WorkerObjectReference{Name: self},
		AuditCredentials: contracts.WorkerObjectReference{Name: contracts.HubAPIName(h.Name, "s3-owner-audit")}}
	recipe, err := providerconfig.OwnerProviderRecipeFor(c, profile.AuthMount, "", profile.ServiceAccount, profile.AuditCredentials, now)
	if err != nil {
		return zero, hubAPIInputError("provider-recipe")
	}
	profile.RecipeSHA256 = recipe.Profile.RecipeSHA256
	c.ProviderAuthentication = &profile

	// Native: connector roots from the connector PKI; worker namespaces by name.
	n := h.Native
	connectorRoots, err := r.PKIRoots(ctx, contracts.SmallOpenBaoConnectorPKIMount)
	if err != nil {
		return zero, hubAPIInputError("connector-roots")
	}
	c.Native = &contracts.OwnerNativeDeployment{ConnectorRoots: connectorRoots, WorkerAPIs: []contracts.OwnerNativeWorkerAPI{}, RetentionTopologies: []contracts.OwnerNativeTopology{}, Connections: h.Connections, Concurrency: h.Concurrency}
	for _, namespace := range n.WorkerNamespaces {
		uid, err := r.NamespaceUID(ctx, namespace)
		if err != nil {
			return zero, hubAPIInputError("worker-namespace-uid")
		}
		c.Native.WorkerAPIs = append(c.Native.WorkerAPIs, contracts.OwnerNativeWorkerAPI{ClusterID: ids.ClusterID, Namespace: contracts.WorkerObjectReference{Name: namespace, UID: uid}, Kubernetes: kubernetes})
	}
	// Remote retention topologies are pinned by content (ADR-196) and arrive
	// with the remote-region slice; the hub cluster needs none.
	if len(n.RetentionTopologies) != 0 {
		return zero, hubAPIInputError("retention-topologies")
	}

	// Observation: the owner pin names this workload; the local connector
	// peer comes from the IDs, remote peers from values.
	protection := contracts.WorkloadSourceDigest(ids.ClusterID, h.Namespace, self)
	protectionHex := hex.EncodeToString(protection[:])
	o := &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: protectionHex, ImageDigest: protectionHex, ProtectionDigest: protectionHex,
		Peers: []contracts.OwnerObservationPeer{{InstallationID: ids.InstallationID, ClusterID: ids.ClusterID, IssuerEpoch: ids.IssuerEpoch, PeerID: ids.PeerID, Roots: connectorRoots}}}
	for _, p := range h.Observation.Peers {
		roots, err := providerconfig.TrustRootsPEM([]byte(p.RootsPEM), now)
		if err != nil {
			return zero, hubAPIInputError("peer-roots")
		}
		o.Peers = append(o.Peers, contracts.OwnerObservationPeer{InstallationID: ids.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: ids.IssuerEpoch, PeerID: p.PeerID, Roots: roots})
	}
	if l := h.Observation.LocalCapacity; l != nil {
		// The hub-worker is the caller of the local capacity observation.
		worker := contracts.HubAPIName(h.Name, "hub-worker")
		accountUID, err := r.ObjectUID(ctx, "", "serviceaccounts", h.Namespace, worker)
		if err != nil {
			return zero, hubAPIInputError("caller-account-uid")
		}
		deploymentUID, err := r.ObjectUID(ctx, "apps", "deployments", h.Namespace, worker)
		if err != nil {
			return zero, hubAPIInputError("caller-deployment-uid")
		}
		caller := contracts.WorkloadSourceDigest(ids.ClusterID, h.Namespace, worker)
		callerHex := hex.EncodeToString(caller[:])
		local := &contracts.OwnerLocalCapacityObservation{Keys: l.Keys, ProbeNamespace: c.Namespace,
			Caller: contracts.OwnerObservationCaller{Account: worker, AccountUID: accountUID, Deployment: worker, DeploymentUID: deploymentUID, TemplateDigest: callerHex, ImageDigest: callerHex, ProtectionDigest: protectionHex}}
		if len(l.LabelKeys)+len(l.AnnotationKeys) > 0 {
			local.WorkloadGuard = &contracts.WorkloadMetadataGuard{LabelKeys: l.LabelKeys, AnnotationKeys: l.AnnotationKeys}
		}
		o.LocalCapacity = local
	}
	c.Observation = o

	if h.Public != nil {
		if c.Public, err = buildHubAPIPublic(ctx, files, c, h, ids, r, configMapUID, now); err != nil {
			return zero, err
		}
	}
	if err = validateOwnerDeployment(c); err != nil {
		return zero, err
	}
	return c, nil
}

func buildHubAPIPublic(ctx context.Context, files *os.Root, c contracts.OwnerDeployment, h contracts.HubAPIConfig, ids hubAPIIDs, r hubAPIResolver, configMapUID func(string, string, string) (contracts.WorkerObjectReference, error), now time.Time) (*contracts.OwnerPublicDeployment, error) {
	ns, p := c.Namespace.Name, *h.Public
	name := func(suffix string) string { return contracts.HubAPIName(h.Name, suffix) }
	providerRoots, err := readCA(ctx, files, contracts.HubAPIIdentityCAFile, now)
	if err != nil {
		return nil, err
	}
	names := providerconfig.OpenBaoNamesFor(ids.InstallationID)
	transit := contracts.SmallOpenBaoTransitMount
	out := &contracts.OwnerPublicDeployment{Format: contracts.OwnerPublicDeploymentFormat, Origin: p.Origin, BrowserRootID: ids.BrowserRootID, BrowserSessionEpoch: ids.SessionEpoch, BrowserAudience: p.BrowserAudience, ProviderRoots: providerRoots,
		SessionTransit: contracts.OwnerPublicTransit{Mount: transit, Key: names.BrowserSessionKey}, CaptureHistory: p.CaptureHistory, Standby: p.Standby, Captures: p.Captures, PreviewSeconds: p.PreviewSeconds, ArtifactKeyID: artifactKeyID(ids.InstallationID),
		DownloadPlan: p.DownloadPlan, ProxyTLS: p.ProxyTLS, Port: contracts.OwnerInstalledPublicPort, Version: p.Version, OperationConcurrency: p.OperationConcurrency, MCPPerIdentity: p.MCPPerIdentity,
		DownloadConcurrency: p.DownloadConcurrency, DownloadsPerIdentity: p.DownloadsPerIdentity, DownloadMaxSeconds: p.DownloadMaxSeconds, OperationAudit: p.OperationAudit, PermissionDelegations: p.PermissionDelegations,
		WorkSigning: contracts.OwnerPublicSigning{Mount: transit, Name: names.WorkSigningKey}, WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: contracts.SmallOpenBaoWorkerPKIMount, Role: names.DownloadWorkerRole, IssuerEpoch: ids.IssuerEpoch}}
	for _, v := range []struct {
		name, step string
		target     *contracts.WorkerObjectReference
	}{{name("browser-settings"), "browser-settings", &out.BrowserSettings}, {name("identity-settings"), "identity-settings", &out.IdentitySettings}, {name("cluster-catalog"), "cluster-catalog", &out.ClusterCatalog.Source}, {name("download-environment"), "download-environment", &out.DownloadEnvironment.Source}} {
		if *v.target, err = configMapUID(ns, v.name, v.step); err != nil {
			return nil, err
		}
	}
	out.DownloadEnvironment.Paths = []contracts.DownloadEnvironmentPath{}
	// The worker profile lives in the download-worker namespace when one is
	// configured (ADR-204 decision 2).
	workerNamespace := ns
	if w := c.Native.WorkerAPIs; len(w) == 1 {
		workerNamespace = w[0].Namespace.Name
	}
	if out.WorkerConfiguration.Source, err = configMapUID(workerNamespace, name("worker-profile"), "worker-configuration"); err != nil {
		return nil, err
	}
	if p.Processing {
		source, err := configMapUID(ns, name("processing-source"), "processing")
		if err != nil {
			return nil, err
		}
		out.Processing = &contracts.OwnerPublicEnvironment{Source: source, Paths: []contracts.DownloadEnvironmentPath{}}
	}
	if out.WorkerPKI.Roots, err = r.PKIRoots(ctx, out.WorkerPKI.Mount); err != nil {
		return nil, hubAPIInputError("worker-roots")
	}
	pin, err := r.CapacityPin(ctx, c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, hubAPIInputError("capacity-qualification")
	}
	policy, err := decodeAuditPolicy(pin.CapturePolicy, "capture", c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, hubAPIInputError("capture-policy")
	}
	out.CaptureAuditPolicy, out.AuditStoreID = pin.CapturePolicy, policy.StoreID
	out.OperationAudit.RetentionSeconds = int(pin.OperationRetentionSeconds)
	out.Capacity = contracts.OwnerPublicCapacity{QualificationID: pin.QualificationID, QualificationDigest: pin.QualificationDigest, AccountVersion: pin.AccountVersion}
	if f := p.Fleet; f != nil {
		settings, err := configMapUID(ns, name("fleet"), "fleet-settings")
		if err != nil {
			return nil, err
		}
		out.Fleet = &contracts.OwnerFleetIssuance{Settings: settings, ChannelMount: contracts.SmallOpenBaoBootstrapMount, DeliveryProfile: f.DeliveryProfile}
	}
	// The work-signing key is read with the work-sign provider role; its role
	// name does not depend on the key version.
	c.Public = out
	roles, _, err := providerconfig.OwnerPublicProviderRecipeFor(c, *c.ProviderAuthentication, now)
	if err != nil {
		return nil, hubAPIInputError("public-recipe")
	}
	version, public, err := r.SigningKey(ctx, roles[2].Name, out.WorkSigning.Mount, out.WorkSigning.Name)
	if err != nil {
		return nil, hubAPIInputError("work-signing-key")
	}
	out.WorkSigning.Version, out.WorkSigning.PublicKey = version, public
	out.WorkSigning.KeyID = out.WorkSigning.Name + "-v" + strconv.Itoa(version)
	if _, out.ProviderRecipeSHA256, err = providerconfig.OwnerPublicProviderRecipeFor(c, *c.ProviderAuthentication, now); err != nil {
		return nil, hubAPIInputError("public-recipe")
	}
	if out.Fleet != nil {
		if _, out.Fleet.ProviderRecipeSHA256, err = providerconfig.OwnerFleetProviderRecipeFor(c, *c.ProviderAuthentication, now); err != nil {
			return nil, hubAPIInputError("fleet-recipe")
		}
	}
	return out, nil
}

// liveHubAPIResolver is the production resolver: the hub-api's own API
// token, OpenBao's unauthenticated CA endpoints and one provider login, and
// the capacity profile reader's SQL login.
type liveHubAPIResolver struct {
	files *providerInputs
	uids  *kube.UIDReader
	// keyService and roots are known once the CA files are read.
	keyService string
	roots      [][]byte
	public     *providerInputs
}

func (r *liveHubAPIResolver) NamespaceUID(ctx context.Context, name string) (string, error) {
	return r.uids.Namespace(ctx, name)
}
func (r *liveHubAPIResolver) ObjectUID(ctx context.Context, group, resource, namespace, name string) (string, error) {
	return r.uids.Object(ctx, group, resource, namespace, name)
}
func (r *liveHubAPIResolver) PKIRoots(ctx context.Context, mount string) ([][]byte, error) {
	return kms.ReadPKIRoots(ctx, r.keyService, r.roots, mount)
}
func (r *liveHubAPIResolver) SigningKey(ctx context.Context, role, mount, name string) (int, ed25519.PublicKey, error) {
	jwt, err := r.files.token(contracts.OwnerProviderTokenFile)(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer clear(jwt)
	return kms.ReadSigningPublicKey(ctx, r.keyService, r.roots, contracts.SmallOpenBaoOwnerAuthMount, role, jwt, mount, name)
}
func (r *liveHubAPIResolver) CapacityPin(ctx context.Context, root, installation string) (postgres.CapacityQualificationPin, error) {
	role := "capacity-profile-read"
	name, known := postgres.PublicRuntimeRoleName(installation, role)
	if !known || r.public == nil {
		return postgres.CapacityQualificationPin{}, mounts.ErrUnavailable
	}
	config, err := r.public.sqlConfig(ctx, "sql-public-"+role+".json")
	if err != nil || config.ConnConfig.User != name {
		return postgres.CapacityQualificationPin{}, mounts.ErrUnavailable
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return postgres.CapacityQualificationPin{}, mounts.ErrUnavailable
	}
	defer pool.Close()
	return postgres.ReadCapacityQualificationPin(ctx, pool, root, installation)
}

// loadHubAPIInputs reads the Helm-native inputs. files is the credential
// root (contracts.OwnerDeploymentRoot); configRoot and idsRoot the config
// and IDs mounts; public the public projection root, or nil.
func loadHubAPIInputs(ctx context.Context, files, configRoot, idsRoot, public *os.Root) (*ownerInputs, error) {
	h, err := readHubAPIConfig(ctx, configRoot)
	if err != nil {
		return nil, err
	}
	ids, err := readHubAPIIDs(ctx, idsRoot)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	kubeRoots, err := readCA(ctx, files, contracts.HubAPIKubernetesCAFile, now)
	if err != nil {
		return nil, err
	}
	keyRoots, err := readCA(ctx, files, contracts.HubAPIKeyServiceCAFile, now)
	if err != nil {
		return nil, err
	}
	pgRoots, err := readCA(ctx, files, contracts.HubAPIPostgresCAFile, now)
	if err != nil {
		return nil, err
	}
	base := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: contracts.HubAPIKubernetesEndpoint, Roots: kubeRoots},
		postgresEndpoint: contracts.OwnerPostgresEndpoint{Host: h.Postgres.Host, Port: h.Postgres.Port, Database: h.Postgres.Database, Roots: pgRoots, MaxConnections: contracts.HubAPIPostgresConnections}}
	defer base.closeHTTP()
	uids, err := kube.NewUIDReader(base.kubernetes(contracts.HubAPIKubernetesTokenFile))
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	resolver := &liveHubAPIResolver{files: base, uids: uids, keyService: h.OpenBao.Endpoint, roots: keyRoots}
	if public != nil {
		resolver.public = &providerInputs{files: public, postgresEndpoint: base.postgresEndpoint}
		defer resolver.public.closeHTTP()
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	c, err := buildHubAPIDeployment(call, files, h, ids, resolver, now)
	if err != nil {
		return nil, err
	}
	offer, err := buildHubAPIRegionalOffer(call, files, h, ids, c.Native.ConnectorRoots, now)
	if err != nil {
		return nil, err
	}
	var control *hubAPIDownloadControl
	if workers := c.Public != nil && len(c.Native.WorkerAPIs) == 1; workers || offer != nil {
		// The evidence store the hub-local download workers read and the
		// combined-mode regional executor writes.
		pin, err := resolver.CapacityPin(call, c.PermissionRootID, c.InstallationID)
		if err != nil {
			return nil, hubAPIInputError("capacity-qualification")
		}
		if workers {
			if control, err = buildHubAPIDownloadControl(call, files, h, c, pin.EvidenceStoreID, now); err != nil {
				return nil, err
			}
		}
		if offer != nil {
			if err = offer.addExecutor(call, files, h, c, pin.EvidenceStoreID, now); err != nil {
				return nil, err
			}
		}
	}
	return &ownerInputs{providerInputs: &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}, config: c, offer: offer, downloadControl: control}, nil
}
