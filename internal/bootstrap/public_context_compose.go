package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	audit "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/contextstart"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publicCapabilities routes each target to its cluster's hub-held capability
// (ADR-179). A cluster without an installed capability is unavailable.
type publicCapabilities map[string]*kube.ContextCapabilitySource

func (c publicCapabilities) ContextCapability(ctx context.Context, t authorization.Target) (planning.ContextCapability, error) {
	s := c[t.ClusterID]
	if s == nil {
		return planning.ContextCapability{}, cfg.ErrUnavailable
	}
	return s.ContextCapability(ctx, t)
}

// publicSigners routes work signing to the target cluster's hub-held trust:
// one hub key signs, but each cluster's trust decides whether it may.
type publicSigners map[string]*jose.APIContextWorkSignatures

func (s publicSigners) SignAPIContextWork(ctx context.Context, w fleet.APIContextWork) ([]byte, error) {
	signer := s[w.Target.ClusterID]
	if signer == nil || w.Channel.Connector.Binding.ClusterID != w.Target.ClusterID {
		return nil, fleet.ErrUnavailable
	}
	return signer.SignAPIContextWork(ctx, w)
}

// publicContext holds the ADR-180 P3 services: the investigation, its audit
// intents, the hub-run regional start, progress and cases.
type publicContext struct {
	investigation captureapp.ContextInvestigation
	intents       auditapp.CaptureOperationPublication
	regional      RegionalAPIContextStart
	progress      captureapp.ContextProgressService
	cases         catalogapp.ContextCaseService
	starts        *OwnerContextStartRuntimeConfig
	retention     privacyapp.RetentionResolver
	permissions   *postgres.Permissions
	catalog       *postgres.ContextPublications
	recovery      *postgres.RecoveryReader
	mac           *auditapp.OperationMAC
	// clusters is the guarded cluster catalog read at start and its digest
	// (ADR-196 decision 3): a later change restarts the process.
	clusters       *kube.ClusterCatalogSource
	clustersDigest [32]byte
	// fleet is the ADR-193 bootstrap issuance; nil without Public.Fleet.
	fleet *fleetapp.FleetBootstrapIssuance
}

func decodeAuditPolicy(raw json.RawMessage, lane, root, installation string) (audit.OperationLifecyclePolicy, error) {
	var p audit.OperationLifecyclePolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 16<<10 || d.Decode(&p) != nil || d.More() || !p.Valid() || p.Lane != lane || p.RootID != root || p.InstallationID != installation || p.History == nil {
		return audit.OperationLifecyclePolicy{}, mounts.ErrUnavailable
	}
	b, e := json.Marshal(p)
	a, z := jsontext.Value(raw), jsontext.Value(b)
	if e != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) {
		return audit.OperationLifecyclePolicy{}, mounts.ErrUnavailable
	}
	return p, nil
}

func publicDigest(s string) (artifact.Digest, bool) {
	var d artifact.Digest
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != len(d) || hex.EncodeToString(b) != s {
		return d, false
	}
	copy(d[:], b)
	return d, d != artifact.Digest{}
}

// publicAuditStore is the owner's audit store and audit Transit keys, shared
// by owner enrollment audit and the public capture/operation audit lanes.
type publicAuditStore struct {
	store *objectstore.Store
	seal  *kms.Sealer
	open  *kms.Opener
	keys  *http.Client
}

// publicShared are the owner native composition's retention topology and
// effect guards; the public layer uses the identical instances.
type publicShared struct {
	topologies configapp.RetentionTopologyReader
	guards     postgres.EffectTransactionGuards
	nativeRead *pgxpool.Pool
	// workers are the pinned worker-namespace clients of Native.WorkerAPIs;
	// origins the native download-peer origins over them.
	workers map[ownerNativeAPIKey]*kube.PermissionClient
	origins evidence.NativeOrigins
}

// files is the public root; providers, in the installed layout, replace the
// work-signing token file (ADR-182).
func newPublicContext(ctx context.Context, in *ownerInputs, files *providerInputs, providers *kms.InstalledOwnerProviderEffects, pools *publicPools, observer, probe *kube.PermissionClient, shared publicShared, catalog publicCatalog, a publicAuditStore, closers *[]func()) (*publicContext, error) {
	c, p := in.config, in.config.Public
	root, installation := c.PermissionRootID, c.InstallationID
	if p == nil || c.Native == nil || pools == nil || observer == nil || probe == nil || shared.topologies == nil || shared.nativeRead == nil || a.store == nil || a.seal == nil || a.open == nil || a.keys == nil ||
		!authorization.UUID(p.ClusterCatalog.Source.UID) || p.Standby < 1 || p.Standby > 64 || p.Captures < 1 || p.Captures > 16 || c.Native.Connections+p.Standby > 64 || p.PreviewSeconds < 1 || p.PreviewSeconds > 300 {
		return nil, mounts.ErrUnavailable
	}
	open := func(purpose string) (*pgxpool.Pool, error) { return pools.open(ctx, purpose) }
	need := func(purposes ...string) (map[string]*pgxpool.Pool, error) {
		out := make(map[string]*pgxpool.Pool, len(purposes))
		for _, purpose := range purposes {
			pool, e := open(purpose)
			if e != nil {
				return nil, e
			}
			out[purpose] = pool
		}
		return out, nil
	}
	sql, err := need("identity-read", "permission-read", "retention-read", "storage-read", "processing-read", "progress-read", "case-read", "catalog-read", "capture-preview", "capture-admit", "capture-resolution", "capture-intent-read", "capture-journal", "capture-ack", "api-execution-read", "api-execution-prepare", "api-execution-record")
	if err != nil {
		return nil, err
	}
	out := &publicContext{}
	if out.recovery, err = postgres.NewRecoveryReader(ctx, sql["identity-read"], installation); err != nil {
		return nil, mounts.ErrUnavailable
	}
	if out.mac, err = newPublicOperationMAC(ctx, files, in.config.InstallationID, pools.manifest); err != nil {
		return nil, mounts.ErrUnavailable
	}
	capture, err := decodeAuditPolicy(p.CaptureAuditPolicy, "capture", root, installation)
	if err != nil {
		return nil, err
	}
	// One hub signing key; each cluster's hub-held trust decides acceptance.
	s := p.WorkSigning
	if !ownerProviderName.MatchString(s.Mount) || !ownerProviderName.MatchString(s.Name) || s.Version < 1 || len(s.PublicKey) != 32 || len(s.KeyID) < 1 || len(s.KeyID) > 128 {
		return nil, mounts.ErrUnavailable
	}
	var key *kms.SigningKey
	if providers != nil {
		if key = providers.WorkSigner(); key == nil {
			return nil, mounts.ErrUnavailable
		}
	} else {
		if key, err = kms.NewSigningKeyWithTokenSource(c.KeyService.Endpoint, s.Mount, s.Name, s.Version, s.PublicKey, files.token(contracts.OwnerPublicWorkSignToken), a.keys); err != nil {
			return nil, mounts.ErrUnavailable
		}
		*closers = append(*closers, key.Close)
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	capabilities, signers := publicCapabilities{}, publicSigners{}
	limits := contextstart.RouterLimits{Standby: p.Standby, Captures: p.Captures}
	// An empty catalog leaves this explicitly empty: the ingress then admits
	// no connector (ADR-185).
	admissions := []mtls.ContextStartConnectorAdmission{}
	// ADR-185: the regional clusters come from the guarded catalog, read once
	// at start before the native configuration (ADR-196 decision 7). Each
	// entry still passes the SQL registry and guard checks below; an empty
	// catalog yields a router that refuses every start.
	if catalog.source == nil {
		return nil, mounts.ErrUnavailable
	}
	out.clusters, out.clustersDigest = catalog.source, catalog.digest
	for _, v := range catalog.catalog.Clusters {
		if _, dup := capabilities[v.ClusterID]; dup || !authorization.UUID(v.ClusterID) || v.Settings.ClusterID != v.ClusterID || v.Trust.ClusterID != v.ClusterID || v.Settings.RootID != root || v.Trust.RootID != root || v.Settings.InstallationID != installation || v.Trust.InstallationID != installation {
			return nil, mounts.ErrUnavailable
		}
		profile, err := publicConnectorProfile(v, root, installation)
		if err != nil {
			return nil, err
		}
		startup, okStartup := publicDigest(v.Executor.StartupDigest)
		image, okImage := publicDigest(v.Executor.ImageDigest)
		if !okStartup || !okImage {
			return nil, mounts.ErrUnavailable
		}
		registry, err := postgres.NewConnectorObservationRegistry(ctx, shared.nativeRead, profile)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		admissions = append(admissions, mtls.ContextStartConnectorAdmission{Profile: profile, Executor: mtls.ContextStartExecutorPin{NamespaceUID: v.Executor.NamespaceUID, AccountUID: v.Executor.AccountUID, StartupDigest: startup, ImageDigest: image}, Registry: registry})
		ca, cp := capacityWorkerGuard(v.Capability.Guard)
		capGuard, err := kube.NewContextCapabilityProtection(observer, probe, cfg.ConfigMapAdministration{Name: v.Capability.Guard.Name, SourceName: v.Capability.Source.Name, ControlNamespace: control, Administrators: ca}, cp)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		capabilities[v.ClusterID], err = kube.NewContextCapabilitySource(observer, capGuard, out.recovery, v.Capability.Source.Name, v.Capability.Source.UID, v.Settings)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		ta, tp := capacityWorkerGuard(v.WorkTrust.Guard)
		trustGuard, err := kube.NewAPIContextWorkTrustProtection(observer, probe, cfg.ConfigMapAdministration{Name: v.WorkTrust.Guard.Name, SourceName: v.WorkTrust.Source.Name, ControlNamespace: control, Administrators: ta}, tp)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		trust, err := kube.NewAPIContextWorkTrustSource(observer, trustGuard, out.recovery, v.WorkTrust.Source.Name, v.WorkTrust.Source.UID, v.Trust)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		if signers[v.ClusterID], err = jose.NewAPIContextWorkSignatures(trust, s.KeyID, key.ForContext, time.Now); err != nil {
			return nil, mounts.ErrUnavailable
		}
		limits.Clusters = append(limits.Clusters, contextstart.ClusterLimit{ClusterID: v.ClusterID, Standby: v.Standby, Captures: v.Captures})
	}
	router, err := contextstart.NewRouter(limits)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	*closers = append(*closers, router.Close)
	out.starts = &OwnerContextStartRuntimeConfig{RootID: root, Router: router, Admissions: admissions, Connections: p.Standby, Preflight: p.Standby}

	recovery := shared.guards.Recovery
	if out.permissions, err = postgres.NewPermissions(ctx, sql["permission-read"], root); err != nil {
		return nil, mounts.ErrUnavailable
	}
	sources, err := postgres.NewRetentionSources(ctx, sql["retention-read"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	// ADR-179: no selector reader; selector policies refuse new collection.
	accepted := privacyapp.AcceptedRetentionReader{Topology: shared.topologies, Sources: sources, Now: time.Now}
	out.retention = privacyapp.RetentionResolver{Policies: accepted, RetainedPolicies: accepted, Now: time.Now}
	eligibility := authapp.Evaluator{Permissions: out.permissions, Now: time.Now}
	previews, err := postgres.NewContextPreviews(ctx, sql["capture-preview"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	admissionsSQL, err := postgres.NewAuditedContextAdmissions(ctx, sql["capture-admit"], root, out.mac, shared.guards)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	resolution, err := postgres.NewContextRequestResolutions(ctx, sql["capture-resolution"], root, recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	storage, err := postgres.NewContextStorageReader(ctx, sql["storage-read"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	processing, err := postgres.NewProcessingReads(ctx, sql["processing-read"], root, recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.investigation = captureapp.ContextInvestigation{RootID: root, InstallationID: installation, Previews: previews, Replay: admissionsSQL, Admission: admissionsSQL, Resolution: resolution,
		Targets: contextstart.Targets{Router: router, Now: time.Now}, Eligibility: eligibility, Capabilities: capabilities, Retention: out.retention, Storage: storage, Processing: processing, Recovery: out.recovery,
		Lifetime: time.Duration(p.PreviewSeconds) * time.Second}

	completed, err := postgres.NewCaptureOperationIntents(ctx, sql["capture-intent-read"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	journal, err := postgres.NewCaptureAuditJournal(ctx, sql["capture-journal"], capture)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	acks, err := postgres.NewCaptureAuditAcknowledgements(ctx, sql["capture-ack"], capture)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	writer, err := objectstore.NewClosedOperationAuditObjects(a.store, capture.StoreID, a.seal, a.open)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.intents = auditapp.CaptureOperationPublication{RootID: root, Completed: completed, Journal: journal, Acknowledgements: acks, Writer: writer, Reader: &objectstore.OperationAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}, MAC: out.mac}

	runner := executionapp.APIContextRunner{Eligibility: eligibility, Retention: out.retention}
	for purpose, port := range map[string]func(*postgres.APIContextExecutions){
		"api-execution-read":    func(x *postgres.APIContextExecutions) { runner.Read = x },
		"api-execution-prepare": func(x *postgres.APIContextExecutions) { runner.Prepare = x },
		"api-execution-record":  func(x *postgres.APIContextExecutions) { runner.Record = x },
	} {
		x, err := postgres.NewAPIContextExecutions(ctx, sql[purpose], root, shared.guards)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		port(x)
	}
	out.regional = RegionalAPIContextStart{Runner: runner, Signer: signers, Router: router}

	progress, err := postgres.NewContextProgressReads(ctx, sql["progress-read"], root, recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.progress = captureapp.ContextProgressService{RootID: root, InstallationID: installation, Reader: progress}
	routes, err := postgres.NewContextCaseReads(ctx, sql["case-read"], root, recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if out.catalog, err = postgres.NewContextPublications(ctx, sql["catalog-read"], root); err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.cases = catalogapp.ContextCaseService{RootID: root, InstallationID: installation, Routes: routes, Permissions: out.permissions, Catalog: out.catalog, Retention: out.retention, Processing: processing}
	if out.fleet, err = newPublicFleet(ctx, c, providers, pools, observer, probe, a); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

// publicConnectorProfile decodes a workload cluster's pinned connector
// identity source exactly as the federation does; its cluster is fixed.
func publicConnectorProfile(v contracts.OwnerPublicCluster, root, installation string) (fleet.ConnectorCredentialProfile, error) {
	profile, _, err := publicConnectorIdentity(v, root, installation)
	return profile, err
}

// publicConnectorIdentity also returns the staged source's six duty roles.
func publicConnectorIdentity(v contracts.OwnerPublicCluster, root, installation string) (fleet.ConnectorCredentialProfile, fleet.ConnectorIdentityRoles, error) {
	var wire contracts.ConnectorIdentityConfiguration
	if json.Unmarshal(v.Connector.Source, &wire) != nil || wire.ClusterID != v.ClusterID {
		return fleet.ConnectorCredentialProfile{}, fleet.ConnectorIdentityRoles{}, mounts.ErrUnavailable
	}
	binding := fleet.PeerBinding{InstallationID: installation, ClusterID: wire.ClusterID, IssuerEpoch: wire.IssuerEpoch, PeerID: wire.PeerID, Role: fleet.ConnectorPeer}
	config, _, err := kube.DecodeConnectorIdentityConfiguration(v.Connector.Source, v.Connector.SourceUID, root, binding, time.Now())
	protection, ok := publicDigest(v.Connector.ProtectionDigest)
	if err != nil || !ok {
		return fleet.ConnectorCredentialProfile{}, fleet.ConnectorIdentityRoles{}, mounts.ErrUnavailable
	}
	profile := config.Source.Observation.Profile
	profile.ProtectionDigest = protection
	if !profile.Valid() || profile.Suspended {
		return fleet.ConnectorCredentialProfile{}, fleet.ConnectorIdentityRoles{}, mounts.ErrUnavailable
	}
	return profile, config.Source.Roles, nil
}

// publicCatalog is the guarded cluster catalog as read at process start.
type publicCatalog struct {
	source  *kube.ClusterCatalogSource
	catalog contracts.OwnerClusterCatalog
	digest  [32]byte
}

// readPublicClusterCatalog reads the guarded catalog once at process start,
// before the native configuration: its entries carry the joined slots'
// retention topology pins (ADR-196 decision 7).
func readPublicClusterCatalog(ctx context.Context, c contracts.OwnerDeployment, observer, probe *kube.PermissionClient) (publicCatalog, error) {
	var out publicCatalog
	p := c.Public
	if p == nil {
		return out, mounts.ErrUnavailable
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	ka, kp := capacityWorkerGuard(p.ClusterCatalog.Guard)
	guard, err := kube.NewClusterCatalogProtection(observer, probe, cfg.ConfigMapAdministration{Name: p.ClusterCatalog.Guard.Name, SourceName: p.ClusterCatalog.Source.Name, ControlNamespace: control, Administrators: ka}, kp)
	if err != nil {
		return out, mounts.ErrUnavailable
	}
	if out.source, err = kube.NewClusterCatalogSource(observer, guard, p.ClusterCatalog.Source.Name, p.ClusterCatalog.Source.UID); err != nil {
		return out, mounts.ErrUnavailable
	}
	if out.catalog, err = out.source.ReadClusterCatalog(ctx); err != nil {
		return out, mounts.ErrUnavailable
	}
	if out.digest, err = clusterCatalogDigest(out.catalog); err != nil {
		return out, mounts.ErrUnavailable
	}
	return out, nil
}

// clusterCatalogDigest identifies the catalog the process started with.
func clusterCatalogDigest(c contracts.OwnerClusterCatalog) ([32]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}
