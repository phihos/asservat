package providerconfig

import (
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
)

type ownerProviderSetupRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
}

// OwnerProviderSetupArtifact emits public instructions for the independently
// administered provider. It applies nothing, adopts nothing and cannot replace
// VerifyOwner's current named readback. Provider/reviewer/SQL/S3 credentials are
// never part of this artifact. The caller must already possess original actual
// account/source/pool identities; an empty future source UID is not generated.
//
// A federation deployment with provider authentication adds its own roles,
// connector PKI roles and audit transit key to the same artifact (ADR-193),
// so the operator applies both compartments in one step. A publisher
// deployment adds its roles, verifier PKI role and audit transit key and
// describes its two operator storage credentials (ADR-203).
func OwnerProviderSetupArtifact(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, pool fleet.OwnerPool, roots [][]byte, now time.Time, federation *contracts.FederationDeployment, publisher *contracts.PublisherDeployment) ([]byte, error) {
	if !authorization.UUID(in.ConfigurationUID) {
		return nil, ErrSetupUnavailable
	}
	setup, err := OwnerSetupRecipeFor(in, profile, pool, roots, now)
	if err != nil {
		return nil, err
	}
	requests := make([]ownerProviderSetupRequest, 10)
	for i, role := range setup.Authentication.Roles {
		body, e := ownerProviderCanonical(struct {
			Policy string `json:"policy"`
		}{string(role.Policy)})
		if e != nil {
			return nil, e
		}
		requests[2*i] = ownerProviderSetupRequest{Method: "POST", Path: "sys/policies/acl/" + role.Name, Body: body}
		requests[2*i+1] = ownerProviderSetupRequest{Method: "POST", Path: "auth/" + profile.AuthMount + "/role/" + role.Name, Body: role.Role}
	}
	for i, role := range setup.PKIRoles {
		requests[8+i] = ownerProviderSetupRequest{Method: "POST", Path: in.KeyService.PKIMount + "/roles/" + role.Name, Body: role.Role}
	}
	// These are the exact existing persisted owner audit key formats. They are
	// installation-scoped, unlike configuration audit's source-UID prefix. Do
	// not claim finer provider IAM isolation than the actual object format.
	storage := struct {
		Store                contracts.OwnerAuditStore       `json:"store"`
		Credentials          contracts.WorkerObjectReference `json:"credentials"`
		SecretKey            string                          `json:"secretKey"`
		CredentialSchema     string                          `json:"credentialSchema"`
		Prefixes             []string                        `json:"prefixes"`
		Operations           [3]string                       `json:"operations"`
		Semantics            string                          `json:"semantics"`
		BackendQualification string                          `json:"backendQualification"`
	}{in.AuditStore, profile.AuditCredentials, contracts.OwnerProviderAuditCredentialFile, "https://asservat.io/spec/v1/owner-credentials.schema.json",
		[]string{"hub-owner-enrollment/v1/" + in.InstallationID + "/", "hub-owner-certificate/v1/" + in.InstallationID + "/"},
		[3]string{"PutObject", "GetObject", "GetObjectVersion"}, "conditional-create/immutable-non-null-version/no-runtime-delete-or-versioning-change", "required"}
	inspect := ownerSetupPaths(in, setup)
	public := in.Public != nil && in.Public.SessionTransit.Key != ""
	if public {
		// ADR-194: a promoted owner's public roles, keys and worker PKI role.
		more, paths, prefixes, e := ownerPublicSetup(in, profile, now)
		if e != nil {
			return nil, e
		}
		requests, inspect, storage.Prefixes = append(requests, more...), append(inspect, paths...), append(storage.Prefixes, prefixes...)
	}
	if in.Public != nil && in.Public.Fleet != nil {
		// ADR-193 step 4: the pinned bootstrap-channel role, and the owner
		// principal also writes the issuance-intent audits.
		role, _, e := OwnerFleetProviderRecipeFor(in, profile, now)
		if e != nil || ValidateOwnerFleetProviderRecipe(in, profile, now) != nil {
			return nil, ErrSetupUnavailable
		}
		body, e := ownerProviderCanonical(struct {
			Policy string `json:"policy"`
		}{string(role.Policy)})
		if e != nil {
			return nil, e
		}
		requests = append(requests, ownerProviderSetupRequest{Method: "POST", Path: "sys/policies/acl/" + role.Name, Body: body}, ownerProviderSetupRequest{Method: "POST", Path: "auth/" + profile.AuthMount + "/role/" + role.Name, Body: role.Role})
		inspect = append(inspect, "sys/policies/acl/"+role.Name, "auth/"+profile.AuthMount+"/role/"+role.Name)
		storage.Prefixes = append(storage.Prefixes, "bootstrap-issue/v1/"+in.InstallationID+"/")
	}
	var federationSetup *FederationProviderSetup
	var federationStorage any
	if federation != nil {
		f, err := FederationProviderSetupFor(*federation)
		if err != nil || federation.InstallationID != in.InstallationID || federation.ClusterID != in.ClusterID || federation.PermissionRootID != in.PermissionRootID {
			return nil, ErrSetupUnavailable
		}
		more, err := f.requests(*federation)
		if err != nil {
			return nil, err
		}
		requests, inspect, federationSetup = append(requests, more...), append(inspect, federationSetupPaths(*federation, f)...), &f
		// The federation writes connector operation audits for the permission
		// root and, for ADR-193 bootstraps, the claim and generation-1 audits;
		// its principal is a separate operator credential.
		federationStorage = struct {
			Store            contracts.OwnerAuditStore       `json:"store"`
			Credentials      contracts.WorkerObjectReference `json:"credentials"`
			SecretKey        string                          `json:"secretKey"`
			CredentialSchema string                          `json:"credentialSchema"`
			Prefixes         [3]string                       `json:"prefixes"`
			Operations       [3]string                       `json:"operations"`
			Semantics        string                          `json:"semantics"`
		}{federation.AuditStore, federation.ProviderAuthentication.AuditCredentials, contracts.FederationProviderAuditCredentialFile, "https://asservat.io/spec/v1/owner-credentials.schema.json",
			[3]string{"operation-audit/v1/" + federation.PermissionRootID + "/", "enrollment-claim/v1/" + federation.InstallationID + "/", "cluster-bootstrap/v1/" + federation.InstallationID + "/"}, [3]string{"PutObject", "GetObject", "GetObjectVersion"}, "conditional-create/immutable-non-null-version/no-runtime-delete-or-versioning-change"}
	}
	var publisherSection *publisherArtifact
	if publisher != nil {
		section, more, paths, err := publisherArtifactFor(in, federation, *publisher)
		if err != nil {
			return nil, err
		}
		requests, publisherSection = append(requests, more...), &section
		for _, path := range paths {
			if !slices.Contains(inspect, path) {
				inspect = append(inspect, path)
			}
		}
	}
	return ownerProviderCanonical(struct {
		Format                 string                      `json:"format"`
		ConfigurationUID       string                      `json:"configurationUID"`
		Setup                  OwnerSetupRecipe            `json:"setup"`
		Federation             *FederationProviderSetup    `json:"federation,omitempty"`
		Publisher              *publisherArtifact          `json:"publisher,omitempty"`
		Public                 bool                        `json:"public,omitempty"`
		Apply                  []ownerProviderSetupRequest `json:"apply"`
		Inspect                []string                    `json:"inspect"`
		AuditStorage           any                         `json:"auditStorage"`
		FederationAuditStorage any                         `json:"federationAuditStorage,omitempty"`
		ExternalAdministration bool                        `json:"externalAdministration"`
	}{"asservat-owner-provider-setup/v1", in.ConfigurationUID, setup, federationSetup, publisherSection, public, requests, inspect, storage, federationStorage, true})
}

// publisherArtifact is the publisher's section of the phase-3 artifact
// (ADR-203): its provider setup and the two operator storage credentials it
// needs, each with exactly the operations the publisher performs.
type publisherArtifact struct {
	Setup               PublisherProviderSetup `json:"setup"`
	AuditStorage        publisherStorage       `json:"auditStorage"`
	EvidenceReadStorage publisherStorage       `json:"evidenceReadStorage"`
}
type publisherStorage struct {
	Endpoint             string   `json:"endpoint"`
	Region               string   `json:"region"`
	Bucket               string   `json:"bucket"`
	SecretKey            string   `json:"secretKey"`
	CredentialSchema     string   `json:"credentialSchema"`
	Prefixes             []string `json:"prefixes"`
	Operations           []string `json:"operations"`
	Semantics            string   `json:"semantics"`
	BackendQualification string   `json:"backendQualification"`
}

// publisherArtifactFor binds the publisher to the promoted owner it runs
// beside: same installation, cluster, root, provider and audit store, the
// owner's worker PKI mount and an audit key no other compartment uses.
func publisherArtifactFor(in contracts.OwnerDeployment, federation *contracts.FederationDeployment, p contracts.PublisherDeployment) (publisherArtifact, []ownerProviderSetupRequest, []string, error) {
	var out publisherArtifact
	setup, err := PublisherProviderSetupFor(p)
	endpoint, _ := publisherProviderEndpoint(p)
	if err != nil || p.InstallationID != in.InstallationID || p.ClusterID != in.ClusterID || p.PermissionRootID != in.PermissionRootID || !authorization.UUID(p.PermissionRootID) ||
		!sameSetupEndpoint(endpoint, contracts.OwnerProviderEndpoint{Endpoint: in.KeyService.Endpoint, Roots: in.KeyService.Roots}) ||
		in.Public == nil || in.Public.WorkerPKI.Mount != p.Verifier.PKIMount || in.Public.WorkerPKI.Role == p.Verifier.Role ||
		p.AuditKeys.Mount == in.KeyService.AuditMount && p.AuditKeys.Key == in.KeyService.AuditKey ||
		federation != nil && p.AuditKeys.Mount == federation.KeyService.AuditMount && p.AuditKeys.Key == federation.KeyService.AuditKey ||
		p.AuditStore.Endpoint != in.AuditStore.Endpoint || p.AuditStore.Region != in.AuditStore.Region || p.AuditStore.Bucket != in.AuditStore.Bucket {
		return out, nil, nil, ErrSetupUnavailable
	}
	requests, err := setup.requests(p)
	if err != nil {
		return out, nil, nil, err
	}
	// The verification audit is a versioned control object under the
	// permission root (audit.ContextVerificationKey); reads name its version.
	// Evidence reads name the stored version too; the publisher never lists,
	// writes or deletes evidence.
	schema := "https://asservat.io/spec/v1/owner-credentials.schema.json"
	out = publisherArtifact{Setup: setup,
		AuditStorage: publisherStorage{Endpoint: p.AuditStore.Endpoint, Region: p.AuditStore.Region, Bucket: p.AuditStore.Bucket, SecretKey: contracts.PublisherAuditCredential, CredentialSchema: schema,
			Prefixes: []string{"context-verification/v1/" + p.PermissionRootID + "/"}, Operations: []string{"PutObject", "GetObject", "GetObjectVersion"},
			Semantics: "conditional-create/immutable-non-null-version/no-runtime-delete-or-versioning-change", BackendQualification: "required"},
		EvidenceReadStorage: publisherStorage{Endpoint: p.Evidence.Endpoint, Region: p.Evidence.Region, Bucket: p.Evidence.Bucket, SecretKey: contracts.PublisherEvidenceCredential, CredentialSchema: schema,
			Prefixes: []string{}, Operations: []string{"GetObject", "GetObjectVersion"}, Semantics: "read-only/no-list-write-or-delete", BackendQualification: "required"}}
	return out, requests, publisherSetupPaths(p, setup), nil
}
