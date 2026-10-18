package bootstrap

import (
	"bytes"
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// The publisher polls its queue every two seconds, eight captures at a time
// (ADR-203); each capture's verification is bounded by its own deadlines.
const (
	publisherPollSeconds = 2
	publisherBatch       = 8
)

// installerPublisher is the publisher's deployment input as far as the phase-3
// artifact needs it, and its identity. The workload step completes the input.
type installerPublisher struct {
	deployment contracts.PublisherDeployment
	identity   kube.PublisherIdentity
}

// publisherEnabled: the publisher verifies what regional executors store, so
// it exists exactly when the executor section and a promoted owner do.
func (k *InstallerContinuation) publisherEnabled() bool {
	p := k.input.Public
	return p != nil && p.Promotion != nil && p.Federation != nil && p.Federation.EvidenceStore != nil && p.Federation.KeyServiceEndpoint != ""
}

// PublisherIdentity prepares the ADR-203 publisher before the phase-3 outbox:
// its account, its two empty credential Secrets and its provider recipe, so
// the one owner provider artifact also carries the publisher's roles.
func (k *InstallerContinuation) PublisherIdentity(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment) error {
	if !k.publisherEnabled() {
		return nil
	}
	if k.capacity == nil || len(k.capacity.qualification.Backends) != 1 {
		return mounts.ErrUnavailable
	}
	k.at("publisher/identity")
	installation := k.record.Scope.InstallationID
	id, err := kube.EnsurePublisherIdentity(ctx, k.in.kubernetes("administrator-token"), inventory.Namespace.Name, installation)
	if err != nil {
		return err
	}
	e := k.input.Public.Federation.EvidenceStore
	roots, err := providerconfig.TrustRootsPEM([]byte(e.RootsPEM), time.Now())
	if err != nil || !ownerEndpoint(e.Endpoint) || !identity.Text(e.Region, 128) || !identity.Text(e.Bucket, 63) {
		return mounts.ErrUnavailable
	}
	sql := owner.Postgres
	sql.MaxConnections = int32(len(contracts.PublicRuntimePublisherPurposes()))
	d := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: installation, ClusterID: k.record.Scope.ClusterID, PermissionRootID: owner.PermissionRootID,
		Namespace: inventory.Namespace, Kubernetes: owner.Kubernetes, Postgres: sql, RetentionTopologies: []contracts.OwnerNativeTopology{}, Owner: owner.Guard(), OwnerWorkload: inventory.OwnerDeployment, AuditStore: owner.AuditStore,
		AuditKeys: contracts.PublisherTransit{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, Mount: owner.KeyService.AuditMount, Key: providerconfig.PublisherAuditKey(installation)},
		Evidence:  contracts.PublisherEvidence{Endpoint: e.Endpoint, Roots: roots, Region: e.Region, Bucket: e.Bucket, StoreID: k.capacity.qualification.Backends[0].EvidenceStoreID},
		Verifier: contracts.PublisherVerifier{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, PKIMount: k.input.Public.Promotion.WorkerPKIMount,
			Role: contracts.PublisherVerifierRole(installation)},
		PollSeconds: publisherPollSeconds, Batch: publisherBatch}
	recipe, err := providerconfig.PublisherProviderRecipeFor(d, contracts.PublisherProviderAuthentication{AuthMount: k.input.OwnerProvider.AuthMount,
		AuthMountAccessor: k.input.OwnerProvider.AuthMountAccessor, Namespace: inventory.Namespace, ServiceAccount: id.Account})
	if err != nil {
		return err
	}
	d.ProviderAuthentication = recipe.Profile
	k.publisher = &installerPublisher{deployment: d, identity: id}
	return nil
}

// PublisherCredentials fills the publisher's Secrets from the phase-3 inbox and
// reads back its applied provider setup through the inspection token. It runs
// after promotion: the verifier chain must verify under the worker PKI roots
// that the promoted owner's readback returned.
func (k *InstallerContinuation) PublisherCredentials(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, inbox kube.InstallerInbox, inspector *providerconfig.SetupReader, owner contracts.OwnerDeployment) error {
	p := k.publisher
	if p == nil {
		return nil
	}
	if owner.Public == nil || len(owner.Public.WorkerPKI.Roots) == 0 {
		return mounts.ErrUnavailable
	}
	defer clear(inbox.PublisherAuditCredential)
	defer clear(inbox.EvidenceReadCredential)
	admin := k.in.kubernetes("administrator-token")
	k.at("publisher/credentials")
	for _, c := range []struct {
		payload []byte
		secret  contracts.WorkerObjectReference
		file    string
	}{{inbox.PublisherAuditCredential, p.identity.AuditCredentials, contracts.PublisherAuditCredential}, {inbox.EvidenceReadCredential, p.identity.EvidenceCredentials, contracts.PublisherEvidenceCredential}} {
		if v, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(c.payload)); e != nil || v.AccessKeyID == "" || v.SecretAccessKey == "" {
			return mounts.ErrUnavailable
		}
		if err := kube.FillProviderAuditSecret(ctx, admin, inventory.Namespace.Name, c.secret, c.file, c.payload); err != nil {
			return err
		}
	}
	k.at("publisher/verify")
	p.deployment.Verifier.IssuerRoots = owner.Public.WorkerPKI.Roots
	_, err := inspector.VerifyPublisher(ctx, p.deployment, owner.Public.WorkerPKI.Roots)
	return err
}

// publisherSetup is the publisher input the phase-3 artifact carries, or nil.
func (k *InstallerContinuation) publisherSetup() *contracts.PublisherDeployment {
	if k.publisher == nil {
		return nil
	}
	return &k.publisher.deployment
}

// PublisherWorkload launches the publisher after the key service: its SQL
// projection, then its Deployment with the completed input. Its topology pins
// come from the cluster catalog at startup (ADR-203 decision 6).
func (k *InstallerContinuation) PublisherWorkload(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, owner contracts.OwnerDeployment, keys *contracts.RegionalWrapService) error {
	p := k.publisher
	if p == nil {
		return nil
	}
	if keys == nil || owner.Public == nil || k.publicRoot == nil || k.publicRoles == nil {
		return mounts.ErrUnavailable
	}
	k.at("publisher/projection")
	if err := converge(ctx, time.Minute, func() error {
		return k.publicRoot.WithPublicRoleOperation(ctx, func(op context.Context) error {
			verified, e := k.publicRoles.Verify(op)
			if e != nil {
				return e
			}
			_, e = k.publicRoot.PublishPublisherRuntimeProjection(op, verified)
			return e
		})
	}); err != nil {
		return err
	}
	k.at("publisher/workload")
	d := p.deployment
	d.ClusterCatalog, d.Owner = owner.Public.ClusterCatalog, owner.Guard()
	d.Artifact = contracts.PublisherArtifacts{Endpoint: keys.Endpoint, Roots: keys.Roots, KeyID: keys.KeyID}
	admin, namespace := k.in.kubernetes("administrator-token"), inventory.Namespace.Name
	w, err := kube.BuildPublisherWorkload(namespace, k.plan.Plan.Workload.Image, inventory.OwnerDeployment.Name, d, p.identity)
	if err != nil {
		return err
	}
	if err = kube.EnsureFederationWorkload(ctx, admin, w); err != nil {
		return err
	}
	k.at("publisher/settle")
	settle, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	return kube.AwaitDeploymentsSettled(settle, admin, namespace, w.Deployment.Name)
}
