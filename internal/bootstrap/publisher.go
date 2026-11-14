package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publisher is the ADR-181 asynchronous publication verifier. It publishes
// stored, unpublished API context captures through the unchanged
// ContextPublisher, unwrapping only under its attempt-scoped verifier
// authority. It serves no route and performs no collection. ADR-203: its
// provider credentials are Kubernetes-auth lifetimes gated by the recovery
// state, and its verifier key exists only in this process.
type Publisher struct {
	argumentSources argumentSourceReader
	config          publisherInputs
	queue           *postgres.ContextPublicationQueue
	ledger          evidence.ContextPublicationFacets
	gate            *postgres.APIContextPublicationGate
	audit           *objectstore.ContextVerificationObjects
	// evidence is the read-only evidence store; each capture is verified in
	// the store its accepted SQL registration names.
	evidence  *objectstore.Store
	keys      *http.Client
	scope     authorization.KeyScope
	providers *kms.InstalledPublisherProviderEffects
	verifier  *mtls.VerifierCredentials
	// catalog is the cluster catalog as read at start; a changed digest
	// restarts the process (ADR-203 decision 6).
	catalog publicCatalog
	closers []func()
	once    sync.Once
}

// publisherInputs are the Helm-rendered configuration plus the generated
// installation IDs.
type publisherInputs struct {
	contracts.PublisherConfig
	contracts.ServiceIDs
}

// keyService is the hub-local key service's Service address.
func (c publisherInputs) keyService() string {
	return "https://" + c.Name + "-key-service." + c.Namespace + ".svc:9447"
}

func readPublisherInputs(ctx context.Context, files, ids *os.Root) (publisherInputs, error) {
	c, err := readServiceConfig(ctx, files, contracts.DecodePublisherConfig)
	if err != nil {
		return publisherInputs{}, err
	}
	v, err := readServiceIDs(ctx, ids)
	if err != nil {
		return publisherInputs{}, err
	}
	_, pg := servicePostgres(c.Postgres, nil)
	if !validServiceScope(c.Name, c.Namespace) || c.PollSeconds < 1 || c.PollSeconds > 300 || c.Batch < 1 || c.Batch > 64 || !pg || !validServiceStore(c.AuditStore) || !validServiceStore(c.Evidence) ||
		!ownerEndpoint(c.OpenBao) || !artifactScope(v.InstallationID).Valid() {
		return publisherInputs{}, &fixedStepError{"config", cfg.ErrInvalid}
	}
	if _, err = serviceTopologyPins(c.RetentionTopologies, nil); err != nil {
		return publisherInputs{}, &fixedStepError{"config", err}
	}
	return publisherInputs{c, v}, nil
}

// verifierTLS presents the in-process verifier key-client certificate to the
// local key service only.
func verifierTLS(credentials *mtls.VerifierCredentials, roots [][]byte) (*http.Client, error) {
	pool, _, err := mtls.OwnerTrustRoots(roots, time.Now())
	if err != nil || credentials == nil {
		return nil, mounts.ErrUnavailable
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return mounts.ErrUnavailable },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, GetClientCertificate: credentials.GetClientCertificate}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxIdleConnsPerHost: 2, DisableCompression: true}}, nil
}

// mountedEvidence is the read-only evidence credential's fixed projection.
type mountedEvidence struct{ inputs *providerInputs }

func NewPublisher(ctx context.Context, files, ids *os.Root) (_ *Publisher, err error) {
	// The phase names where startup stopped; causes stay out of the message.
	phase := "inputs"
	defer func() {
		if err != nil {
			err = &fixedStepError{"publisher/" + phase, err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || files == nil || ids == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readPublisherInputs(ctx, files, ids)
	if err != nil {
		return nil, err
	}
	out := &Publisher{config: c}
	complete := false
	defer func() {
		if !complete {
			out.Close()
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	phase = "roots"
	roots := map[string][][]byte{}
	for _, name := range []string{contracts.PostgresRootsFile, contracts.ObjectStoreRootsFile, contracts.OpenBaoRootsFile, contracts.KeyServiceRootsFile} {
		if roots[name], err = readServiceRoots(startup, files, name); err != nil {
			return nil, err
		}
	}
	endpoint, _ := servicePostgres(c.Postgres, roots[contracts.PostgresRootsFile])
	in := &providerInputs{files: files, postgresEndpoint: endpoint}
	out.closers = append(out.closers, in.closeHTTP)
	phase = "sql"
	root, installation := c.PermissionRootID, c.InstallationID
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.PublicRuntimePublisherPurposes() {
		phase = "sql/" + purpose
		// The login is the derived role name; nothing else is verified.
		name, known := postgres.PublicRuntimeRoleName(installation, purpose)
		config, err := in.sqlConfig(startup, "sql-"+purpose+".json")
		if !known || err != nil || config == nil || config.ConnConfig.User != name {
			return nil, mounts.ErrUnavailable
		}
		config.MaxConns, config.MinConns = 1, 0
		pool, err := pgxpool.NewWithConfig(startup, config)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		out.closers = append(out.closers, pool.Close)
		pools[purpose] = pool
	}
	phase = "kubernetes"
	api, err := serviceKubernetes()
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	namespaceUID, err := kube.NamespaceUID(startup, api, c.Namespace)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	observer, err := kube.NewPermissionClient(api, c.ClusterID, cfg.NamespaceRef{Name: c.Namespace, UID: namespaceUID}, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = "catalog"
	// ADR-203 decision 6: the catalog adds the joined slots' topologies.
	if out.catalog, err = readServiceCatalog(startup, observer, api, c.Namespace, c.Name+"-cluster-catalog"); err != nil {
		return nil, err
	}
	phase = "topology"
	pins, err := serviceTopologyPins(c.RetentionTopologies, out.catalog.catalog.Clusters)
	if err != nil {
		return nil, err
	}
	topologies, err := kube.NewRetentionTopologies(observer, root, pins)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	// The hub cluster's own captures (mode=combined) use the in-process hub
	// topology, as in the hub-api, unless a pin names the hub cluster.
	if !slices.ContainsFunc(pins, func(p kube.RetentionTopologyPin) bool { return p.TargetClusterID == c.ClusterID }) {
		if err = topologies.AddHubTopology(observer, root); err != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	for _, cluster := range c.RemoteClusters {
		if err = topologies.AddRemoteTopology(observer, root, cluster); err != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	retentionGuard, err := postgres.NewRetentionTransactionGuard(root, topologies)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = "recovery"
	recoveryGuard, err := postgres.NewRecoveryTransactionGuard(root, installation)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	guards := postgres.EffectTransactionGuards{Retention: retentionGuard, Recovery: recoveryGuard}
	recovery, err := postgres.NewRecoveryReader(startup, pools["publisher-identity-read"], installation)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	sources, err := postgres.NewRetentionSources(startup, pools["publisher-retention-read"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = "publication"
	accepted := privacyapp.AcceptedRetentionReader{Topology: topologies, Sources: sources, Now: time.Now}
	if out.gate, err = postgres.NewAPIContextPublicationGate(startup, pools["publication-gate"], root, guards, privacyapp.RetentionResolver{Policies: accepted, RetainedPolicies: accepted, Now: time.Now}, recovery); err != nil {
		return nil, mounts.ErrUnavailable
	}
	facet := func(purpose string) (*postgres.ContextPublications, error) {
		return postgres.NewContextPublications(startup, pools[purpose], root, guards)
	}
	verify, err := facet("context-verify")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	audited, err := facet("context-verification-audit")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	publish, err := facet("context-publish")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.argumentSources = verify
	out.ledger = evidence.ContextPublicationFacets{ContextAcceptanceReader: verify, ContextVerificationRecorder: verify, ContextVerificationAuditor: audited, ContextCatalogPublisher: publish}
	if out.queue, err = postgres.NewContextPublicationQueue(startup, pools["context-verify"], root); err != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = "providers"
	// ADR-203 decision 3: every provider login and renewal needs a current
	// recovery observation.
	login := serviceLogin(c.Name, c.Namespace, "publisher", contracts.OwnerProviderEndpoint{Endpoint: c.OpenBao, Roots: roots[contracts.OpenBaoRootsFile]}, "audit-wrap", "audit-unwrap", "verifier-sign")
	names := providerconfig.OpenBaoNamesFor(installation)
	keys := kms.PublisherProviderKeys{AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: names.PublisherAuditKey, PKIMount: contracts.SmallOpenBaoWorkerPKIMount, VerifierRole: names.VerifierRole}
	if out.providers, err = kms.NewInstalledPublisherProviderEffects(ctx, installation, login, keys, files, recoveryProof(recovery)); err != nil {
		return nil, mounts.ErrUnavailable
	}
	providers := out.providers
	out.closers = append(out.closers, func() { _ = providers.CloseAndJoin(context.Background()) })
	phase = "audit-store"
	auditHTTP, err := ownerHTTP(c.AuditStore.Endpoint, roots[contracts.ObjectStoreRootsFile])
	if err != nil {
		return nil, err
	}
	out.closers = append(out.closers, auditHTTP.CloseIdleConnections)
	auditStore, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in}, auditHTTP)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, auditStore.Close)
	out.audit = &objectstore.ContextVerificationObjects{Store: auditStore, Seal: providers.Sealer(), Open: providers.Opener()}

	phase = "evidence-store"
	evidenceHTTP, err := ownerHTTP(c.Evidence.Endpoint, roots[contracts.ObjectStoreRootsFile])
	if err != nil {
		return nil, err
	}
	out.closers = append(out.closers, evidenceHTTP.CloseIdleConnections)
	if out.evidence, err = objectstore.New(c.Evidence.Endpoint, c.Evidence.Region, c.Evidence.Bucket, mountedEvidence{in}, evidenceHTTP); err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, out.evidence.Close)
	phase = "verifier"
	// ADR-203 decision 4: the verifier key is created here, after core dumps
	// are disabled, and signed only through the verifier-sign lifetime. The
	// returned chain must verify against the worker PKI CA (field class J).
	issuerRoots, err := readPKIRoots(startup, c.OpenBao, roots[contracts.OpenBaoRootsFile], contracts.SmallOpenBaoWorkerPKIMount)
	if err != nil {
		return nil, err
	}
	issuer, _, err := mtls.OwnerTrustRoots(issuerRoots, time.Now())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if out.verifier, err = mtls.NewVerifierCredentials(installation, providers.VerifierSigner(), issuer, time.Now); err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, out.verifier.Close)
	if out.keys, err = verifierTLS(out.verifier, roots[contracts.KeyServiceRootsFile]); err != nil {
		return nil, err
	}
	out.closers = append(out.closers, out.keys.CloseIdleConnections)
	out.scope = artifactScope(installation)
	if !out.scope.Valid() || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return out, nil
}

// publish verifies and publishes one stored capture. Each attempt has its own
// remote opener bound to that attempt; the key service decides every unwrap.
func (p *Publisher) publish(ctx context.Context, item postgres.PendingContextPublication) error {
	opener, err := kms.NewRemoteOpener(p.config.keyService(), p.scope, item.AttemptID, p.keys)
	if err != nil {
		return err
	}
	// The evidence store ID is the accepted SQL registration's (field class
	// J); the publisher reads exactly one evidence bucket.
	accepted, err := p.ledger.ContextAcceptanceReader.AcceptedContextForPublication(ctx, item.CaptureID)
	if err != nil {
		return err
	}
	custody, err := p.evidence.ForCustody(accepted.Registration.StoreID)
	if err != nil {
		return err
	}
	verifier, err := objectstore.NewContextVerifier(custody, opener)
	if err != nil {
		return err
	}
	// ADR-248: a networkHeaders PCAPNG is rechecked packet by packet in the
	// same verification read (packets.CheckHeadersOnly).
	verifier.WithStreamCheck(artifact.PCAPNGArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return packets.NewHeadersCheck() })
	// ADR-279: a rawPackets PCAPNG is rechecked against its accepted caps.
	verifier.WithStreamCheck(artifact.RawPCAPNGArtifact, func(e artifact.ContextExpectation) objectstore.StreamCheck {
		return packets.NewRawCheck(rawLimits(e.Recording))
	})
	// ADR-282: an HTTP header projection is rechecked as a document: strict
	// canonical decode, the accepted limits and only approved header values.
	verifier.WithStreamCheck(artifact.HTTPHeadersArtifact, func(e artifact.ContextExpectation) objectstore.StreamCheck {
		return httpheaders.NewExpectationCheck(e)
	})
	// ADR-284: a Go endpoint profile is decompressed and parsed within fixed
	// bounds; an execution trace is read to its end within an event cap.
	verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewPprofCheck() })
	verifier.WithStreamCheck(artifact.GoTraceArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewGoTraceCheck() })
	verifier.WithContextStreamCheck(artifact.SyscallArgumentsArtifact, func(ctx context.Context, e artifact.ContextExpectation) (objectstore.StreamCheck, error) {
		return publisherArgumentCheck(ctx, p.argumentSources, e)
	})
	_, err = evidence.ContextPublisher{Ledger: p.ledger, Authority: p.gate, Verifier: verifier, Audit: p.audit, Now: time.Now}.Publish(ctx, item.CaptureID, item.Copies)
	return err
}

// Run funds the provider purposes and the first verifier certificate, then
// polls the bounded queue until ctx ends. A failed capture stays queued and
// is retried within its finite unwrap allowance; nothing is recollected. A
// stopped provider or verifier supervisor stops the process, and a changed
// cluster catalog returns errClusterCatalogChanged so the kubelet restarts it.
func (p *Publisher) Run(ctx context.Context) (err error) {
	phase := "run"
	defer func() {
		if err != nil {
			err = &fixedStepError{"publisher/" + phase, err}
		}
	}()
	if p == nil || p.queue == nil || p.providers == nil || p.verifier == nil || p.catalog.source == nil || ctx == nil {
		return mounts.ErrUnavailable
	}
	phase = "prime"
	if err := p.providers.Prime(ctx); err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	work, stop := context.WithCancel(ctx)
	var joined sync.WaitGroup
	defer func() { stop(); joined.Wait() }()
	joined.Add(1)
	go func() { defer joined.Done(); _ = p.providers.Run(work); stop() }()
	phase = "verifier-renew"
	first, end := context.WithTimeout(work, 30*time.Second)
	err = p.verifier.Renew(first)
	end()
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	joined.Add(1)
	go func() { defer joined.Done(); _ = p.verifier.Run(work); stop() }()
	phase = "queue"
	// Closed outcome words only; a capture that keeps failing stays visible.
	report := eventLog(os.Stderr, "publisher")
	poll := time.NewTimer(0)
	defer poll.Stop()
	catalog := time.NewTicker(15 * time.Second)
	defer catalog.Stop()
	for {
		select {
		case <-work.Done():
			if ctx.Err() != nil {
				return nil
			}
			phase = "supervisor"
			return mounts.ErrUnavailable // a supervisor ended
		case <-catalog.C:
			// A failed read is not a change.
			if p.clusterCatalogChanged(work) {
				phase = "catalog-changed"
				return errClusterCatalogChanged
			}
		case <-poll.C:
			read, cancel := context.WithTimeout(work, 5*time.Second)
			pending, err := p.queue.PendingContextPublications(read, p.config.Batch)
			cancel()
			if err != nil {
				report("queue " + errorClass(err))
			}
			for _, item := range pending {
				call, end := context.WithTimeout(work, 30*time.Second)
				if e := p.publish(call, item); e != nil {
					stage := ""
					var staged *evidence.PublicationStageError
					if errors.As(e, &staged) {
						stage = " at " + staged.Stage
					}
					var step interface{ FixedStep() string }
					if errors.As(e, &step) {
						stage += "/" + step.FixedStep()
					}
					report("publish " + errorClass(e) + stage)
				} else {
					report("published")
				}
				end()
			}
			poll.Reset(time.Duration(p.config.PollSeconds) * time.Second)
		}
	}
}

func (p *Publisher) clusterCatalogChanged(ctx context.Context) bool {
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	catalog, err := p.catalog.source.ReadClusterCatalog(call)
	if err != nil {
		return false
	}
	digest, err := clusterCatalogDigest(catalog)
	return err == nil && digest != p.catalog.digest
}

func (p *Publisher) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		for i := len(p.closers) - 1; i >= 0; i-- {
			p.closers[i]()
		}
	})
}

// RunPublisher is the `asservat publisher` entry point.
func RunPublisher(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.PublisherDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	ids, err := os.OpenRoot(contracts.IDsRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer ids.Close()
	// The setup Job creates the worker PKI and provider state after this
	// Pod starts: wait in-process for them.
	var p *Publisher
	if err = waitStartup(ctx, "publisher", startupLog, func(ctx context.Context) (err error) {
		p, err = NewPublisher(ctx, files, ids)
		return err
	}, nil); err != nil {
		return err
	}
	defer p.Close()
	return p.Run(ctx)
}

func (s mountedEvidence) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := s.inputs.read(ctx, contracts.PublisherEvidenceCredential, 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 4096) || (c.SessionToken != "" && !identity.Text(c.SessionToken, 16384)) {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "protected-publisher-evidence-read"}, nil
}

// rawLimits are an accepted rawPackets recording's prefix caps; zero (refused
// by the check) for anything else.
func rawLimits(r *artifact.Recording) packets.RawLimits {
	if r == nil || r.Profile != "rawPackets" {
		return packets.RawLimits{}
	}
	l := packets.RawLimits{Snaplen: r.Snaplen}
	if c := r.ProtocolSnaplen; c != nil {
		l.TCP, l.UDP, l.ICMP = c.TCP, c.UDP, c.ICMP
	}
	return l
}
