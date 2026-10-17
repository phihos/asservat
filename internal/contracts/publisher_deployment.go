package contracts

import "io"

// ADR-181: the asynchronous publication verifier's installation-owned inputs.
// Credentials and keys are fixed projected files under PublisherDeploymentRoot.
const (
	PublisherDeploymentFormat       = "asservat-publisher-deployment/v1"
	PublisherDeploymentRoot         = "/run/asservat/publisher"
	PublisherDeploymentFile         = "publisher.json"
	PublisherDeploymentMaxBytes     = 64 << 10
	PublisherCredentialManifestFile = "publisher-roles.json"
	PublisherKubernetesToken        = "kube.token"
	PublisherEvidenceCredential     = "evidence-read.json"
	PublisherVerifierCertificate    = "verifier-tls.crt"
	PublisherVerifierKey            = "verifier-tls.key"
)

type PublisherDeployment struct {
	Format              string                `json:"format"`
	InstallationID      string                `json:"installationID"`
	ClusterID           string                `json:"clusterID"`
	PermissionRootID    string                `json:"permissionRootID"`
	Namespace           WorkerObjectReference `json:"namespace"`
	Kubernetes          OwnerProviderEndpoint `json:"kubernetes"`
	Postgres            OwnerPostgresEndpoint `json:"postgres"`
	RetentionTopologies []OwnerNativeTopology `json:"retentionTopologies"`
	// Verification audit: the owner audit store and audit Transit key.
	AuditStore OwnerAuditStore    `json:"auditStore"`
	AuditKeys  PublisherTransit   `json:"auditKeys"`
	Evidence   PublisherEvidence  `json:"evidence"`
	Artifact   PublisherArtifacts `json:"artifact"`
	// PollSeconds and Batch bound the publication queue.
	PollSeconds int `json:"pollSeconds"`
	Batch       int `json:"batch"`
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
