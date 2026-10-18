package providerconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerProviderArtifactDescribesExactExistingEffectsWithoutIssuing(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001490"
	b, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Format           string                        `json:"format"`
		ConfigurationUID string                        `json:"configurationUID"`
		Setup            OwnerSetupRecipe              `json:"setup"`
		Apply            [10]ownerProviderSetupRequest `json:"apply"`
		Inspect          []string                      `json:"inspect"`
		AuditStorage     struct {
			SecretKey            string    `json:"secretKey"`
			CredentialSchema     string    `json:"credentialSchema"`
			Prefixes             [2]string `json:"prefixes"`
			Operations           [3]string `json:"operations"`
			Semantics            string    `json:"semantics"`
			BackendQualification string    `json:"backendQualification"`
		} `json:"auditStorage"`
	}
	if json.Unmarshal(b, &out) != nil || out.Format != "asservat-owner-provider-setup/v1" || out.ConfigurationUID != f.in.ConfigurationUID || len(out.Inspect) != 16 || !out.Setup.ReviewerCredentialRequired || f.requests.Load() != 0 {
		t.Fatal("artifact performed provider work or lost original public scope")
	}
	if out.Inspect[0] != "sys/mounts/auth/"+f.profile.AuthMount || out.AuditStorage.SecretKey != contracts.OwnerProviderAuditCredentialFile || out.AuditStorage.CredentialSchema != "https://asservat.io/spec/v1/owner-credentials.schema.json" {
		t.Fatal("inspection artifact needs elevated auth mount path")
	}
	for i, role := range out.Setup.Authentication.Roles {
		policy, login := out.Apply[2*i], out.Apply[2*i+1]
		var expected struct {
			Policy string `json:"policy"`
		}
		if policy.Method != "POST" || policy.Path != "sys/policies/acl/"+role.Name || json.Unmarshal(policy.Body, &expected) != nil || expected.Policy != string(role.Policy) || login.Method != "POST" || login.Path != "auth/"+f.profile.AuthMount+"/role/"+role.Name || !bytes.Equal(login.Body, role.Role) {
			t.Fatal("artifact lost fixed purpose role/policy body")
		}
	}
	for i, role := range out.Setup.PKIRoles {
		request := out.Apply[8+i]
		if request.Method != "POST" || request.Path != f.in.KeyService.PKIMount+"/roles/"+role.Name || !bytes.Equal(request.Body, role.Role) {
			t.Fatal("artifact lost generated exact PKI recipe")
		}
	}
	id := "10000000-0000-4000-8000-000000001491"
	enrollment := fleet.OwnerEnrollment{ID: id, Binding: fleet.OwnerBinding{InstallationID: f.in.InstallationID}}
	certificate := audit.OwnerCertificate{Attempt: fleet.OwnerCertificateAttempt{Permit: fleet.OwnerCertificatePermit{ID: id}}, Certificate: fleet.OwnerCertificate{Binding: enrollment.Binding}}
	if audit.OwnerEnrollmentKey(enrollment) != out.AuditStorage.Prefixes[0]+id || audit.OwnerCertificateKey(certificate) != out.AuditStorage.Prefixes[1]+id || out.AuditStorage.Operations != [3]string{"PutObject", "GetObject", "GetObjectVersion"} || out.AuditStorage.Semantics != "conditional-create/immutable-non-null-version/no-runtime-delete-or-versioning-change" || out.AuditStorage.BackendQualification != "required" {
		t.Fatal("storage instructions differ from actual persisted audit format")
	}
	for _, forbidden := range []string{`"client_token"`, `"token_reviewer_jwt"`, `"secretAccessKey"`, `"password"`, "DeleteObject", "ListBucket"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("artifact contains credentials or unsupported storage authority", forbidden)
		}
	}
	f.in.ConfigurationUID = ""
	if _, err = OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil); err == nil {
		t.Fatal("artifact invented an unacknowledged future source identity")
	}
	if strings.Contains(string(b), "synthetic-inspection-only") {
		t.Fatal("inspection credential entered public artifact")
	}
}

// ADR-193: one phase-3 artifact also carries the federation's four roles and
// policies, the two connector PKI roles and its audit key; every write is one
// the applier admits, and the federation audit principal is separate.
func TestOwnerProviderArtifactCarriesFederationSetup(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001490"
	f.in.PermissionRootID = "10000000-0000-4000-8000-000000001491"
	fed := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: f.in.InstallationID, ClusterID: f.in.ClusterID, PermissionRootID: f.in.PermissionRootID, AuditStore: f.in.AuditStore,
		KeyService: contracts.FederationKeyService{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, AuditMount: f.in.KeyService.AuditMount, AuditKey: "federation-audit", PKIMount: "connector-pki", ClientRole: "connector-client", ServerRole: "connector-server"}}
	recipe, err := FederationProviderRecipeFor(fed, contracts.FederationProviderAuthentication{AuthMount: f.profile.AuthMount, AuthMountAccessor: f.profile.AuthMountAccessor, Namespace: f.in.Namespace,
		ServiceAccount:   contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(f.in.InstallationID), UID: "10000000-0000-4000-8000-000000001492"},
		AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: "10000000-0000-4000-8000-000000001493"}})
	if err != nil {
		t.Fatal(err)
	}
	fed.ProviderAuthentication = &recipe.Profile
	b, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), &fed, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Federation             *FederationProviderSetup    `json:"federation"`
		Apply                  []ownerProviderSetupRequest `json:"apply"`
		Inspect                []string                    `json:"inspect"`
		FederationAuditStorage struct {
			SecretKey string    `json:"secretKey"`
			Prefixes  [3]string `json:"prefixes"`
		} `json:"federationAuditStorage"`
	}
	if json.Unmarshal(b, &out) != nil || out.Federation == nil || len(out.Apply) != 21 || f.requests.Load() != 0 {
		t.Fatal("federation setup missing or provider work performed", len(out.Apply))
	}
	for _, r := range out.Apply {
		if !setupApplyPath(r.Path) {
			t.Fatal("applier would refuse", r.Path)
		}
	}
	if out.Apply[20].Path != "transit/keys/federation-audit" && !strings.HasSuffix(out.Apply[20].Path, "/keys/federation-audit") {
		t.Fatal("audit key is not the last create-only write", out.Apply[20].Path)
	}
	if out.FederationAuditStorage.SecretKey != contracts.FederationProviderAuditCredentialFile || out.FederationAuditStorage.Prefixes != [3]string{"operation-audit/v1/" + f.in.PermissionRootID + "/", "enrollment-claim/v1/" + f.in.InstallationID + "/", "cluster-bootstrap/v1/" + f.in.InstallationID + "/"} {
		t.Fatal("federation audit principal not separately scoped")
	}
	found := map[string]bool{}
	for _, p := range out.Inspect {
		found[p] = true
	}
	for _, role := range recipe.Roles {
		if !found["auth/"+f.profile.AuthMount+"/role/"+role.Name] || !found["sys/policies/acl/"+role.Name] {
			t.Fatal("federation role not inspectable", role.Name)
		}
	}
	other := fed
	other.PermissionRootID = "10000000-0000-4000-8000-000000001499"
	if _, err = OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), &other, nil, nil, nil); err == nil {
		t.Fatal("federation for another root accepted")
	}
}

// ADR-193 step 4: issuance adds exactly the pinned bootstrap-channel role and
// the owner principal's issuance audit prefix; an unpinned recipe is refused.
func TestOwnerProviderArtifactCarriesFleetChannel(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001494"
	in := f.in
	in.Public = &contracts.OwnerPublicDeployment{Fleet: &contracts.OwnerFleetIssuance{ChannelMount: "fleet-kv", DeliveryProfile: "regional-installer"}}
	if _, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil); err == nil {
		t.Fatal("unpinned fleet recipe accepted")
	}
	role, digest, err := OwnerFleetProviderRecipeFor(in, f.profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in.Public.Fleet.ProviderRecipeSHA256 = digest
	b, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Apply        []ownerProviderSetupRequest `json:"apply"`
		Inspect      []string                    `json:"inspect"`
		AuditStorage struct {
			Prefixes []string `json:"prefixes"`
		} `json:"auditStorage"`
	}
	if json.Unmarshal(b, &out) != nil || len(out.Apply) != 12 || out.Apply[10].Path != "sys/policies/acl/"+role.Name || out.Apply[11].Path != "auth/"+f.profile.AuthMount+"/role/"+role.Name {
		t.Fatal("fleet role requests missing", len(out.Apply))
	}
	for _, r := range out.Apply {
		if !setupApplyPath(r.Path) {
			t.Fatal("applier would refuse", r.Path)
		}
	}
	if len(out.AuditStorage.Prefixes) != 3 || out.AuditStorage.Prefixes[2] != "bootstrap-issue/v1/"+in.InstallationID+"/" || !slices.Contains(out.Inspect, "sys/policies/acl/"+role.Name) {
		t.Fatal("issuance audit prefix or inspection missing")
	}
}

// ADR-194 step 5: a promoted owner adds its four public roles, the two
// create-only Transit keys, the worker PKI role and the public audit
// prefixes; a worker PKI mount shared with the owner PKI is refused.
func TestOwnerProviderArtifactCarriesPromotedPublic(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001495"
	in := f.in
	in.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "public-transit", Name: "work"},
		WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: "10000000-0000-4000-8000-000000001496"}}
	b, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Apply        []ownerProviderSetupRequest `json:"apply"`
		Inspect      []string                    `json:"inspect"`
		AuditStorage struct {
			Prefixes []string `json:"prefixes"`
		} `json:"auditStorage"`
	}
	if json.Unmarshal(b, &out) != nil || len(out.Apply) != 21 || len(out.AuditStorage.Prefixes) != 10 || out.AuditStorage.Prefixes[2] != "operation-audit/v1/"+in.PermissionRootID+"/" {
		t.Fatal("promoted public setup", len(out.Apply), out.AuditStorage.Prefixes)
	}
	var keys []string
	for _, r := range out.Apply {
		if !setupApplyPath(r.Path) {
			t.Fatal("applier would refuse", r.Path)
		}
		if strings.HasPrefix(r.Path, "public-transit/keys/") {
			keys = append(keys, r.Path+" "+string(r.Body))
		}
	}
	if len(keys) != 2 || !strings.Contains(keys[0], `"aes256-gcm96"`) || !strings.Contains(keys[1], `"ed25519"`) || !strings.Contains(keys[1], `"exportable":false`) {
		t.Fatal("transit keys", keys)
	}
	for _, path := range []string{"public-transit/keys/work", "worker-pki/cert/ca", "worker-pki/roles/worker"} {
		if !slices.Contains(out.Inspect, path) {
			t.Fatal("readback path not inspectable", path)
		}
	}
	in.Public.WorkerPKI.Mount = in.KeyService.PKIMount
	if _, err = OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil); err == nil {
		t.Fatal("worker PKI on the owner PKI mount accepted")
	}
}

// ADR-204 decision 5: a promoted owner with downloads names the workers' own
// read-only evidence credential and its operations; it adds no provider
// request, and an artifact without it is byte-identical to before.
func TestOwnerProviderArtifactNamesDownloadEvidenceCredential(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001497"
	in := f.in
	in.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "public-transit", Name: "work"},
		WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: "10000000-0000-4000-8000-000000001496"}}
	store := &contracts.InstallerEvidenceStore{Endpoint: "https://store.synthetic.invalid", Region: "synthetic-region", Bucket: "evidence"}
	now := time.Now()
	base, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, nil, nil)
	if err != nil || bytes.Contains(base, []byte("downloadEvidenceReadStorage")) {
		t.Fatal("artifact without downloads changed", err)
	}
	b, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out, before struct {
		Apply    []ownerProviderSetupRequest `json:"apply"`
		Download *struct {
			Endpoint, Region, Bucket, SecretKey, Semantics string
			Prefixes, Operations                           []string
		} `json:"downloadEvidenceReadStorage"`
	}
	if json.Unmarshal(b, &out) != nil || json.Unmarshal(base, &before) != nil || len(out.Apply) != len(before.Apply) || out.Download == nil ||
		out.Download.Bucket != "evidence" || out.Download.SecretKey != "credentials.json" || !slices.Equal(out.Download.Operations, []string{"GetObject", "GetObjectVersion"}) || len(out.Download.Prefixes) != 0 || out.Download.Semantics != "read-only/no-list-write-or-delete" {
		t.Fatal("download evidence credential", string(b))
	}
	in.Public = nil
	if _, err = OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, store, nil); err == nil {
		t.Fatal("download credential without a promoted owner accepted")
	}
}
