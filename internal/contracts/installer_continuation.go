package contracts

import (
	"strings"
)

// ADR-183: the installer continuation's public inputs. They name operator
// provider choices only; no provider or administration credential is a field.
const (
	InstallerContinuationFormat = "asservat-installer-continuation/v1"
	InstallerContinuationRoot   = "/run/asservat/installer-continue"
	// The installer runner's retirement step refreshes the preparer here.
	InstallerContinuationPreparerRoot = "/run/asservat/initial-preparer"
	// The operator's inbox Secret keys. Only the continuation reads them and
	// deletes the inbox after the phase consumed it.
	InstallerInboxPhase                   = "phase"
	InstallerInboxAuditCredential         = "audit-storage.json"
	InstallerInboxCleanupAuditCredential  = "cleanup-audit.json"
	InstallerInboxCleanupVerifyCredential = "cleanup-verify.json"
)

type InstallerContinuation struct {
	Format         string `json:"format"`
	IdentitySource string `json:"identitySource,omitempty"`
	// ObjectStoreSource selects the fixed public bundled-store projection.
	// Resolve it before ordinary provider consumers; it grants no authority.
	ObjectStoreSource string `json:"objectStoreSource,omitempty"`
	// KeyServiceSource explicitly selects the fixed public bundled provider.
	KeyServiceSource string `json:"keyServiceSource,omitempty"`
	// Optional existing private TLS/OIDC material in the bootstrap namespace.
	// Credentials remain outside values and the public continuation document.
	MaterialSecretName string `json:"materialSecretName,omitempty"`
	// Namespace is the chart's release namespace holding the outbox and inbox;
	// operators cannot write the guarded installation namespace.
	Namespace      string                     `json:"namespace"`
	WorkerProvider InstallerProviderSelection `json:"workerProvider"`
	OwnerProvider  InstallerProviderSelection `json:"ownerProvider"`
	// OwnerIssuerRootsPEM are the owner PKI roots the operator created.
	OwnerIssuerRootsPEM string `json:"ownerIssuerRootsPEM"`
	// The owner bootstrap plan; its one peer is the hub cluster (ADR-179).
	OwnerPKIMount    string `json:"ownerPKIMount"`
	OwnerConnections int    `json:"ownerConnections"`
	OwnerConcurrency int    `json:"ownerConcurrency"`
	// Public names the operator's browser identity choices (ADR-185); absent,
	// the continuation launches an observation-only owner.
	Public *InstallerPublicSettings `json:"public,omitempty"`
}

// InstallerPublicSettings become the browser and identity settings
// ConfigMaps. Revisions, the browser root and the session epoch are generated.
type InstallerPublicSettings struct {
	Processors         []ProcessingOrganization `json:"processors,omitzero"`
	CaptureHistory     *CaptureHistoryLimits    `json:"captureHistory,omitempty"`
	Origin             string                   `json:"origin"`
	Issuer             string                   `json:"issuer"`
	ClientID           string                   `json:"clientID"`
	MaxLifetimeSeconds int                      `json:"maxLifetimeSeconds"`
	MaxLogins          int                      `json:"maxLogins"`
	MaxSessions        int                      `json:"maxSessions"`
	MaxLogoutEvents    int                      `json:"maxLogoutEvents"`
	Clients            []IdentityClient         `json:"clients"`
	EligibleSubjects   []IdentitySubject        `json:"eligibleSubjects"`
	EligibleGroups     []string                 `json:"eligibleGroups"`
	GroupMaxAgeSeconds int                      `json:"groupMaxAgeSeconds"`
	// Approvals passes protected step-up and manual-recording policy unchanged.
	Approvals *IdentityApprovals `json:"approvals,omitempty"`
	// Capacity is the operator's capacity profile and ProcessingOperators the
	// processing release operators (ADR-190). Both are required for capacity.
	Capacity            *InstallerCapacitySettings `json:"capacity,omitempty"`
	ProcessingOperators []ProcessingOperator       `json:"processingOperators,omitempty"`
	// Federation provisions the hub-federation for regional connectors
	// (ADR-193); absent, no regional cluster can enroll.
	Federation *InstallerFederationSettings `json:"federation,omitempty"`
	// RetentionBaseline is the hub baseline retention policy (ADR-195 D2),
	// created after the hub source's first acceptance. Without it captures
	// fail closed until an operator applies a baseline.
	RetentionBaseline *InstallerRetentionBaseline `json:"retentionBaseline,omitempty"`
	// Promotion launches the promoted hub-api with its public layer
	// (ADR-194); absent, the owner launches observation-only. It requires
	// Capacity and Federation.
	Promotion *InstallerOwnerPromotion `json:"promotion,omitempty"`
}

// InstallerOwnerPromotion are the operator's promoted-owner choices without
// defaults (ADR-194 decision 2). Key and role names are derived; limits use
// the documented unqualified defaults.
type InstallerOwnerPromotion struct {
	// BrowserAudience is the browser login's access-token audience and
	// ProviderRootsPEM the identity provider's TLS roots.
	BrowserAudience  string `json:"browserAudience"`
	ProviderRootsPEM string `json:"providerRootsPEM"`
	// TransitMount holds the session and work-signing keys; it must differ
	// from the audit and owner PKI mounts. WorkerPKIMount issues download
	// worker leaves and must differ from the owner PKI mount.
	TransitMount   string `json:"transitMount"`
	WorkerPKIMount string `json:"workerPKIMount"`
	// Version is reported by the hub-api; a chart-driven install sets the
	// chart version.
	Version string `json:"version"`
	// Exposure, when set, publishes the public API on its own L4 Service
	// (ADR-202). TLS ends in the hub-api, so no proxy may terminate it.
	Exposure *InstallerPublicExposure `json:"exposure,omitempty"`
}

// InstallerPublicExposure selects the public API Service: NodePort, with an
// optional fixed node port, or LoadBalancer.
type InstallerPublicExposure struct {
	ServiceType string `json:"serviceType"`
	NodePort    int32  `json:"nodePort,omitempty"`
}

// InstallerFederationSettings are the operator's federation choices.
type InstallerFederationSettings struct {
	// ConnectorPKIMount is the operator-created PKI mount for connector
	// leaves; ConnectorIssuerRootsPEM are its issuer roots.
	ConnectorPKIMount       string `json:"connectorPKIMount"`
	ConnectorIssuerRootsPEM string `json:"connectorIssuerRootsPEM"`
	// Endpoint is the external https URL regional connectors dial and
	// ServerName the name on the operator's serving TLS Secret
	// FederationServingSecretName; TLS ends in the federation Pod.
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"serverName"`
	// ServiceType is LoadBalancer or NodePort (an L4 Service); NodePort, when
	// set, pins the node port the Endpoint names.
	ServiceType string `json:"serviceType"`
	NodePort    int32  `json:"nodePort,omitempty"`
	// OwnerAddress is the host:port regional connectors dial for the owner's
	// native port, through an L4 Service of the same ServiceType (ADR-196
	// decision 5); OwnerNodePort, when set, pins its node port. Without an
	// address the owner is not exposed and the offer names no owners.
	OwnerAddress  string `json:"ownerAddress,omitempty"`
	OwnerNodePort int32  `json:"ownerNodePort,omitempty"`
	// OwnerOperationAddress is the host:port regional standbys dial for the
	// owner's ADR-197 v2 operation port on the same L4 Service;
	// OwnerOperationNodePort, when set, pins its node port. Without it the
	// offer names no regional capacity.
	OwnerOperationAddress  string `json:"ownerOperationAddress,omitempty"`
	OwnerOperationNodePort int32  `json:"ownerOperationNodePort,omitempty"`
	// KeyServiceEndpoint is the https URL regional connectors dial for
	// artifact key wraps (ADR-198), through an L4 Service of the same
	// ServiceType; KeyServiceNodePort, when set, pins its node port. The
	// operator's KeyServiceServingSecretName must name the endpoint's host.
	// Without it no key service is installed and the offer names none.
	KeyServiceEndpoint string `json:"keyServiceEndpoint,omitempty"`
	KeyServiceNodePort int32  `json:"keyServiceNodePort,omitempty"`
	// EvidenceStore, with the key service and owner address, completes the
	// offer's regional executor section (ADR-196 decision 7).
	EvidenceStore *InstallerEvidenceStore `json:"evidenceStore,omitempty"`
	// Connector sizes the installation-wide connector root backing; its
	// backup values come from the capacity profile, which is then required.
	Connector InstallerConnectorSettings `json:"connector"`
	// Fleet, when set, enables the specified fleet-operator bootstrap channel.
	Fleet *InstallerFleetIssuance `json:"fleet,omitempty"`
}

// InstallerFleetIssuance selects the operator's KV-v2 mount and one delivery
// profile from the protected fleet settings (ADR-193).
type InstallerFleetIssuance struct {
	ChannelMount    string `json:"channelMount"`
	DeliveryProfile string `json:"deliveryProfile"`
}

// InstallerConnectorSettings are the operator-qualified connector identity
// retention and footprint. The backing is a standing configuration, valid
// until replaced, with no install-time connector count (ADR-332).
type InstallerConnectorSettings struct {
	RetainedSeconds int64                      `json:"retainedSeconds"`
	PurgeLeases     int64                      `json:"purgeLeases"`
	Footprint       InstallerCapacityFootprint `json:"footprint"`
}

// FederationServingSecretName is the operator's kubernetes.io/tls Secret
// (tls.crt, tls.key, ca.crt) for the federation's serving identity.
func FederationServingSecretName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-federation-tls"
}

// InstallerProviderSelection is an operator-created Kubernetes auth mount.
type InstallerProviderSelection struct {
	AuthMount         string `json:"authMount"`
	AuthMountAccessor string `json:"authMountAccessor"`
}

// InstallerRetentionBaseline is the empty-scope baseline policy's operator
// values; none has a default. Rules and legal exceptions start empty.
type InstallerRetentionBaseline struct {
	PurposeRef            string                      `json:"purposeRef"`
	Defaults              InstallerRetentionDurations `json:"defaults"`
	Maxima                InstallerRetentionDurations `json:"maxima"`
	DeletionBudgetSeconds int64                       `json:"deletionBudgetSeconds"`
}
type InstallerRetentionDurations struct {
	EvidenceSeconds      int64 `json:"evidenceSeconds"`
	CaseMetadataSeconds  int64 `json:"caseMetadataSeconds"`
	AuditMetadataSeconds int64 `json:"auditMetadataSeconds"`
}
