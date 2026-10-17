package providerconfig

import (
	"encoding/json"
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
// so the operator applies both compartments in one step.
func OwnerProviderSetupArtifact(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, pool fleet.OwnerPool, roots [][]byte, now time.Time, federation *contracts.FederationDeployment) ([]byte, error) {
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
	return ownerProviderCanonical(struct {
		Format                 string                      `json:"format"`
		ConfigurationUID       string                      `json:"configurationUID"`
		Setup                  OwnerSetupRecipe            `json:"setup"`
		Federation             *FederationProviderSetup    `json:"federation,omitempty"`
		Public                 bool                        `json:"public,omitempty"`
		Apply                  []ownerProviderSetupRequest `json:"apply"`
		Inspect                []string                    `json:"inspect"`
		AuditStorage           any                         `json:"auditStorage"`
		FederationAuditStorage any                         `json:"federationAuditStorage,omitempty"`
		ExternalAdministration bool                        `json:"externalAdministration"`
	}{"asservat-owner-provider-setup/v1", in.ConfigurationUID, setup, federationSetup, public, requests, inspect, storage, federationStorage, true})
}
