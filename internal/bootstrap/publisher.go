package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publisher is the ADR-181 asynchronous publication verifier. It publishes
// stored, unpublished API context captures through the unchanged
// ContextPublisher, unwrapping only under its attempt-scoped verifier
// authority. It serves no route and performs no collection.
type Publisher struct {
	config  contracts.PublisherDeployment
	queue   *postgres.ContextPublicationQueue
	ledger  evidence.ContextPublicationFacets
	gate    *postgres.APIContextPublicationGate
	audit   *objectstore.ContextVerificationObjects
	custody *objectstore.CustodyStore
	keys    *http.Client
	scope   authorization.KeyScope
	closers []func()
	once    sync.Once
}

func readPublisherInputs(ctx context.Context, files *os.Root) (*providerInputs, contracts.PublisherDeployment, contracts.PublicRuntimeCredentialManifest, error) {
	var c contracts.PublisherDeployment
	var m contracts.PublicRuntimeCredentialManifest
	fail := func() (*providerInputs, contracts.PublisherDeployment, contracts.PublicRuntimeCredentialManifest, error) {
		return nil, contracts.PublisherDeployment{}, contracts.PublicRuntimeCredentialManifest{}, mounts.ErrUnavailable
	}
	b, err := mounts.Read(ctx, files, contracts.PublisherDeploymentFile, contracts.PublisherDeploymentMaxBytes)
	if err != nil {
		return fail()
	}
	c, err = contracts.DecodePublisherDeployment(bytes.NewReader(b))
	clear(b)
	if err != nil || c.Format != contracts.PublisherDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.ClusterID) || !authorization.UUID(c.PermissionRootID) || !capacityRuntimeReference(c.Namespace) ||
		c.PollSeconds < 1 || c.PollSeconds > 300 || c.Batch < 1 || c.Batch > 64 || len(c.RetentionTopologies) < 1 || len(c.RetentionTopologies) > 1024 ||
		!authorization.UUID(c.Evidence.StoreID) || !identity.Text(c.Evidence.Region, 128) || !identity.Text(c.Evidence.Bucket, 63) || !identity.Text(c.Artifact.KeyID, 128) ||
		!ownerProviderName.MatchString(c.AuditKeys.Mount) || !ownerProviderName.MatchString(c.AuditKeys.Key) || !identity.Text(c.AuditStore.Region, 128) || !identity.Text(c.AuditStore.Bucket, 63) {
		return fail()
	}
	for _, ep := range []contracts.OwnerProviderEndpoint{c.Kubernetes, {Endpoint: c.AuditStore.Endpoint, Roots: c.AuditStore.Roots}, {Endpoint: c.AuditKeys.Endpoint, Roots: c.AuditKeys.Roots}, {Endpoint: c.Evidence.Endpoint, Roots: c.Evidence.Roots}, {Endpoint: c.Artifact.Endpoint, Roots: c.Artifact.Roots}} {
		if !capacityRuntimeEndpoint(ep) {
			return fail()
		}
	}
	p := c.Postgres
	if p.Port < 1 || p.Port > 65535 || !identity.Text(p.Database, 63) || !identity.Text(p.Host, 253) {
		return fail()
	}
	if _, _, err = mtls.OwnerTrustRoots(p.Roots, time.Now()); err != nil {
		return fail()
	}
	b, err = mounts.Read(ctx, files, contracts.PublisherCredentialManifestFile, contracts.PublicRuntimeCredentialManifestMaxBytes)
	if err != nil {
		return fail()
	}
	m, err = contracts.DecodePublicRuntimeCredentialManifest(bytes.NewReader(b))
	clear(b)
	if err != nil || m.Input.InstallationID != c.InstallationID || m.Input.ClusterID != c.ClusterID || m.Input.Namespace != c.Namespace {
		return fail()
	}
	return &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}, c, m, nil
}

// verifierTLS presents the mounted verifier key-client pair, following its
// rotation, to the local key service only.
func verifierTLS(in *providerInputs, roots [][]byte) (*http.Client, error) {
	pool, _, err := mtls.OwnerTrustRoots(roots, time.Now())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	get := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		crt, err := mounts.Read(ctx, in.files, contracts.PublisherVerifierCertificate, 64<<10)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		key, err := mounts.Read(ctx, in.files, contracts.PublisherVerifierKey, 64<<10)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(crt, key)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		return &pair, nil
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return mounts.ErrUnavailable },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, GetClientCertificate: get}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxIdleConnsPerHost: 2, DisableCompression: true}}, nil
}

// mountedEvidence is the read-only evidence credential's fixed projection.
type mountedEvidence struct{ inputs *providerInputs }

func NewPublisher(ctx context.Context, files *os.Root) (*Publisher, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	in, c, manifest, err := readPublisherInputs(ctx, files)
	if err != nil {
		return nil, err
	}
	out := &Publisher{config: c}
	out.closers = append(out.closers, in.closeHTTP)
	complete := false
	defer func() {
		if !complete {
			out.Close()
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	root, installation := c.PermissionRootID, c.InstallationID
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range contracts.PublicRuntimePublisherPurposes() {
		name, known := postgres.PublicRuntimeRoleName(installation, purpose)
		config, err := in.sqlConfig(startup, "sql-public-"+purpose+".json")
		if !known || err != nil || config == nil || config.ConnConfig.User != name {
			return nil, mounts.ErrUnavailable
		}
		config.MaxConns, config.MinConns = 1, 0
		pool, err := pgxpool.NewWithConfig(startup, config)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		out.closers = append(out.closers, pool.Close)
		if postgres.VerifyPublisherRuntimeCredential(startup, pool, manifest, purpose) != nil {
			return nil, mounts.ErrUnavailable
		}
		pools[purpose] = pool
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observer, err := kube.NewPermissionClient(in.kubernetes(contracts.PublisherKubernetesToken), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	pins := make([]kube.RetentionTopologyPin, len(c.RetentionTopologies))
	for i, p := range c.RetentionTopologies {
		b, err := hex.DecodeString(p.SHA256)
		if err != nil || len(b) != 32 || !authorization.UUID(p.TargetClusterID) || !authorization.UUID(p.UID) {
			return nil, mounts.ErrUnavailable
		}
		pins[i] = kube.RetentionTopologyPin{TargetClusterID: p.TargetClusterID, Name: p.Name, UID: p.UID}
		copy(pins[i].ContentDigest[:], b)
	}
	topologies, err := kube.NewRetentionTopologies(observer, root, pins)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	retentionGuard, err := postgres.NewRetentionTransactionGuard(root, topologies)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
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
	out.ledger = evidence.ContextPublicationFacets{ContextAcceptanceReader: verify, ContextVerificationRecorder: verify, ContextVerificationAuditor: audited, ContextCatalogPublisher: publish}
	if out.queue, err = postgres.NewContextPublicationQueue(startup, pools["context-verify"], root); err != nil {
		return nil, mounts.ErrUnavailable
	}

	h, err := ownerHTTP(c.AuditKeys.Endpoint, c.AuditKeys.Roots)
	if err != nil {
		return nil, err
	}
	out.closers = append(out.closers, h.CloseIdleConnections)
	seal, err := kms.NewSealerWithTokenSource(c.AuditKeys.Endpoint, c.AuditKeys.Mount, c.AuditKeys.Key, in.token("audit-wrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, seal.Close)
	opener, err := kms.NewOpenerWithTokenSource(c.AuditKeys.Endpoint, c.AuditKeys.Mount, c.AuditKeys.Key, in.token("audit-unwrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, opener.Close)
	auditHTTP, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
	if err != nil {
		return nil, err
	}
	out.closers = append(out.closers, auditHTTP.CloseIdleConnections)
	auditStore, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in}, auditHTTP)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, auditStore.Close)
	out.audit = &objectstore.ContextVerificationObjects{Store: auditStore, Seal: seal, Open: opener}

	evidenceHTTP, err := ownerHTTP(c.Evidence.Endpoint, c.Evidence.Roots)
	if err != nil {
		return nil, err
	}
	out.closers = append(out.closers, evidenceHTTP.CloseIdleConnections)
	store, err := objectstore.New(c.Evidence.Endpoint, c.Evidence.Region, c.Evidence.Bucket, mountedEvidence{in}, evidenceHTTP)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	out.closers = append(out.closers, store.Close)
	if out.custody, err = store.ForCustody(c.Evidence.StoreID); err != nil {
		return nil, mounts.ErrUnavailable
	}
	if out.keys, err = verifierTLS(in, c.Artifact.Roots); err != nil {
		return nil, err
	}
	out.closers = append(out.closers, out.keys.CloseIdleConnections)
	out.scope = authorization.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: c.Artifact.KeyID}
	if !out.scope.Valid() || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return out, nil
}

// publish verifies and publishes one stored capture. Each attempt has its own
// remote opener bound to that attempt; the key service decides every unwrap.
func (p *Publisher) publish(ctx context.Context, item postgres.PendingContextPublication) error {
	opener, err := kms.NewRemoteOpener(p.config.Artifact.Endpoint, p.scope, item.AttemptID, p.keys)
	if err != nil {
		return err
	}
	verifier, err := objectstore.NewContextVerifier(p.custody, opener)
	if err != nil {
		return err
	}
	_, err = evidence.ContextPublisher{Ledger: p.ledger, Authority: p.gate, Verifier: verifier, Audit: p.audit, Now: time.Now}.Publish(ctx, item.CaptureID, item.Copies)
	return err
}

// Run polls the bounded queue until ctx ends. A failed capture stays queued
// and is retried within its finite unwrap allowance; nothing is recollected.
func (p *Publisher) Run(ctx context.Context) error {
	if p == nil || p.queue == nil || ctx == nil {
		return mounts.ErrUnavailable
	}
	ticker := time.NewTicker(time.Duration(p.config.PollSeconds) * time.Second)
	defer ticker.Stop()
	for {
		read, cancel := context.WithTimeout(ctx, 5*time.Second)
		pending, err := p.queue.PendingContextPublications(read, p.config.Batch)
		cancel()
		if err == nil {
			for _, item := range pending {
				call, end := context.WithTimeout(ctx, 30*time.Second)
				_ = p.publish(call, item)
				end()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
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
	p, err := NewPublisher(ctx, files)
	if err != nil {
		return err
	}
	defer p.Close()
	return p.Run(ctx)
}

func (s mountedEvidence) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := mounts.Read(ctx, s.inputs.files, contracts.PublisherEvidenceCredential, 32<<10)
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
