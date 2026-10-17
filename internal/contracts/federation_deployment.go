package contracts

import (
	"encoding/json"
	"io"
	"strings"
)

// ADR-170 federation process: installation-owned public startup inputs at a
// fixed root. Credentials have fixed separate projected filenames and cannot
// be embedded or redirected through this document.
const FederationDeploymentFormat = "asservat-federation-deployment/v1"
const FederationDeploymentRoot = "/run/asservat/federation"
const FederationDeploymentMaxBytes = 1 << 20
const FederationAuditKeysFormat = "asservat-federation-audit-keys/v1"

// FederationPort is the federation's container port; its L4 Service maps the
// operator's external endpoint to it (ADR-193).
const FederationPort = 9446

type FederationDeployment struct {
	Format           string                `json:"format"`
	InstallationID   string                `json:"installationID"`
	ClusterID        string                `json:"clusterID"`
	PermissionRootID string                `json:"permissionRootID"`
	Port             int                   `json:"port"`
	Postgres         OwnerPostgresEndpoint `json:"postgres"`
	AuditStore       OwnerAuditStore       `json:"auditStore"`
	KeyService       FederationKeyService  `json:"keyService"`
	// ADR-193: no peer list. Each presented peer resolves to its staged SQL
	// connector profile; a peer that was never staged is refused.
	Concurrency int `json:"concurrency"`
	// Owner enables the ADR-172 owner purposes. Observer and probe tokens are
	// the fixed projected files kube-observer.token and kube-probe.token.
	Owner *OwnerGuardInputs `json:"owner,omitempty"`
	// ProviderAuthentication selects OpenBao Kubernetes auth for the four
	// provider purposes (ADR-193). Without it the legacy static token files
	// remain the only provider credential source.
	ProviderAuthentication *FederationProviderAuthentication `json:"providerAuthentication,omitempty"`
	// Connector is the installation-wide connector block (ADR-193); without
	// it the bootstrap purpose stays refused.
	Connector *FederationConnector `json:"connector,omitempty"`
}

// FederationConnector holds the hub-decided connector root backing (an
// application ConnectorIdentityBacking). A first staging under bootstrap
// authority must name exactly this backing; once the root exists, its stored
// backing is the reference instead.
type FederationConnector struct {
	Backing json.RawMessage `json:"backing"`
}

const FederationProviderAuthenticationFormat = "asservat-federation-kubernetes-auth/v1"

// FederationProviderTokenFile is the projected service account token with
// the federation provider audience; FederationProviderAuditCredentialFile is
// the operator's audit storage principal.
const FederationProviderTokenFile = "provider-auth.token"
const FederationProviderAuditCredentialFile = "provider-audit-storage.json"

// FederationProviderAudience derives the fixed audience of the federation's
// projected provider token; it grants no authority.
func FederationProviderAudience(installationID, clusterID string) string {
	return "https://asservat." + installationID + "/federation-provider/" + clusterID
}

// FederationProviderAuthentication is the public, installation-owned
// selection of the federation's Kubernetes auth roles. It holds no JWT,
// provider token or secret payload.
type FederationProviderAuthentication struct {
	Format            string                `json:"format"`
	AuthMount         string                `json:"authMount"`
	AuthMountAccessor string                `json:"authMountAccessor"`
	Namespace         WorkerObjectReference `json:"namespace"`
	ServiceAccount    WorkerObjectReference `json:"serviceAccount"`
	AuditCredentials  WorkerObjectReference `json:"auditCredentials"`
	RecipeSHA256      string                `json:"recipeSHA256"`
}

// FederationServiceAccountName is the federation's fixed account name.
func FederationServiceAccountName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-federation"
}

type FederationKeyService struct {
	Endpoint   string   `json:"endpoint"`
	Roots      [][]byte `json:"roots"`
	AuditMount string   `json:"auditMount"`
	AuditKey   string   `json:"auditKey"`
	PKIMount   string   `json:"pkiMount"`
	ClientRole string   `json:"clientRole"`
	ServerRole string   `json:"serverRole"`
}

// FederationPeer pins one regional connector exactly as installed: the
// original source ConfigMap UID, its exact document bytes and the regional
// namespace guard's protection digest (hex). The hub-api catalog and the key
// service use it; the federation resolves peers from SQL instead (ADR-193).
type FederationPeer struct {
	SourceUID        string          `json:"sourceUID"`
	ProtectionDigest string          `json:"protectionDigest"`
	Source           json.RawMessage `json:"source"`
}

// FederationAuditKeys are the connector operation/account MAC keys; the
// account version must equal each staged peer backing's AccountVersion.
type FederationAuditKeys struct {
	Format         string `json:"format"`
	InstallationID string `json:"installationID"`
	RootID         string `json:"rootID"`
	InputVersion   string `json:"inputVersion"`
	InputKey       []byte `json:"inputKey"`
	AccountVersion string `json:"accountVersion"`
	AccountKey     []byte `json:"accountKey"`
}

func DecodeFederationDeployment(r io.Reader) (FederationDeployment, error) {
	return decodeClosedRPC[FederationDeployment](r, FederationDeploymentMaxBytes)
}
func DecodeFederationAuditKeys(r io.Reader) (FederationAuditKeys, error) {
	return decodeClosedRPC[FederationAuditKeys](r, 16<<10)
}

// ConnectorServerSuffix is the installation's connector server-name domain
// (ADR-193): each regional connector serves as <cluster-id>.<suffix>, which
// the installation-wide connector PKI server role constrains by glob.
func ConnectorServerSuffix(installationID string) string {
	return "connector.asservat." + installationID
}
