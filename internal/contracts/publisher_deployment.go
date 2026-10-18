package contracts

import (
	"io"
	"strings"
)

// ADR-181: the asynchronous publication verifier's installation-owned inputs.
// Credentials are fixed projected files under PublisherDeploymentRoot; the
// verifier key exists only in the process (ADR-203).
const (
	PublisherDeploymentFormat       = "asservat-publisher-deployment/v1"
	PublisherDeploymentRoot         = "/run/asservat/publisher"
	PublisherDeploymentFile         = "publisher.json"
	PublisherDeploymentMaxBytes     = 64 << 10
	PublisherCredentialManifestFile = "publisher-roles.json"
	// PublisherKubernetesToken (observer) and PublisherProbeToken are the
	// account's projected API tokens for the guard proof and catalog read.
	PublisherKubernetesToken = "kube-observer.token"
	PublisherProbeToken      = "kube-probe.token"
	// PublisherProviderTokenFile is the projected token with the publisher
	// provider audience (ADR-203 decision 3).
	PublisherProviderTokenFile = "provider-auth.token"
	// PublisherEvidenceCredential and PublisherAuditCredential are the
	// operator's storage principals (ADR-203 decision 5).
	PublisherEvidenceCredential = "evidence-read.json"
	PublisherAuditCredential    = "audit-storage.json"
)

const PublisherProviderAuthenticationFormat = "asservat-publisher-kubernetes-auth/v1"

// PublisherProviderAudience derives the fixed audience of the publisher's
// projected provider token; it grants no authority.
func PublisherProviderAudience(installationID, clusterID string) string {
	return "https://asservat." + installationID + "/publisher-provider/" + clusterID
}

// PublisherName is the publisher's Deployment and ServiceAccount name.
func PublisherName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-publisher"
}

// PublisherVerifierRole is the worker PKI role that signs only
// key-client/verifier URIs (ADR-203 decision 4).
func PublisherVerifierRole(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-verifier"
}

type PublisherDeployment struct {
	Format           string                `json:"format"`
	InstallationID   string                `json:"installationID"`
	ClusterID        string                `json:"clusterID"`
	PermissionRootID string                `json:"permissionRootID"`
	Namespace        WorkerObjectReference `json:"namespace"`
	Kubernetes       OwnerProviderEndpoint `json:"kubernetes"`
	Postgres         OwnerPostgresEndpoint `json:"postgres"`
	// RetentionTopologies are fixed pins; the guarded cluster catalog adds
	// the joined slots' pins at startup. Either may be empty (ADR-203).
	RetentionTopologies []OwnerNativeTopology    `json:"retentionTopologies"`
	ClusterCatalog      OwnerPublicGuardedSource `json:"clusterCatalog"`
	// Owner is the hub namespace's workload guard; its current proof and the
	// recovery state gate every provider login and renewal.
	Owner OwnerGuardInputs `json:"owner"`
	// Verification audit: the owner audit store and audit Transit key.
	AuditStore OwnerAuditStore    `json:"auditStore"`
	AuditKeys  PublisherTransit   `json:"auditKeys"`
	Evidence   PublisherEvidence  `json:"evidence"`
	Artifact   PublisherArtifacts `json:"artifact"`
	// Verifier is the worker PKI mount and role that sign the in-process
	// verifier key-client certificate.
	Verifier               PublisherVerifier               `json:"verifier"`
	ProviderAuthentication PublisherProviderAuthentication `json:"providerAuthentication"`
	// PollSeconds and Batch bound the publication queue.
	PollSeconds int `json:"pollSeconds"`
	Batch       int `json:"batch"`
}

// PublisherProviderAuthentication is the public, installation-owned
// selection of the publisher's Kubernetes auth roles. It holds no JWT,
// provider token or secret payload.
type PublisherProviderAuthentication struct {
	Format            string                `json:"format"`
	AuthMount         string                `json:"authMount"`
	AuthMountAccessor string                `json:"authMountAccessor"`
	Namespace         WorkerObjectReference `json:"namespace"`
	ServiceAccount    WorkerObjectReference `json:"serviceAccount"`
	RecipeSHA256      string                `json:"recipeSHA256"`
}

// PublisherVerifier names the OpenBao PKI that signs verifier certificates.
type PublisherVerifier struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	PKIMount string   `json:"pkiMount"`
	Role     string   `json:"role"`
}
type PublisherTransit struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	Mount    string   `json:"mount"`
	Key      string   `json:"key"`
}

// PublisherEvidence is the read-only evidence store credential's target.
type PublisherEvidence struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	Region   string   `json:"region"`
	Bucket   string   `json:"bucket"`
	StoreID  string   `json:"storeID"`
}

// PublisherArtifacts is the local key service and its artifact key.
type PublisherArtifacts struct {
	Endpoint string   `json:"endpoint"`
	Roots    [][]byte `json:"roots"`
	KeyID    string   `json:"keyID"`
}

func DecodePublisherDeployment(r io.Reader) (PublisherDeployment, error) {
	return decodeClosedRPC[PublisherDeployment](r, PublisherDeploymentMaxBytes)
}
