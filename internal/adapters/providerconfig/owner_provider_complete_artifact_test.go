package providerconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerProviderArtifactCompletePromotedInstallationFits(t *testing.T) {
	f := newSetupFixture(t)
	now := time.Now()
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001490"
	f.in.PermissionRootID = "10000000-0000-4000-8000-000000001491"
	prefix := "asservat-" + strings.ReplaceAll(f.in.InstallationID, "-", "")
	// Use installation-derived names and an explicit bounded auth mount, rather
	// than the short names used by individual provider component fixtures.
	f.in.Namespace.Name = "bootstrap-chain-10000000-target"
	f.in.KeyService.AuditMount = "bootstrap-chain-transit"
	f.in.KeyService.PKIMount = "owner-pki"
	f.in.KeyService.ClientRole = prefix + "-owner-client"
	f.in.KeyService.ServerRole = prefix + "-owner-server"
	f.pool.Namespace = f.in.Namespace.Name
	f.pool.ServiceAccount = prefix + "-owner"
	ownerRecipe, err := OwnerProviderRecipeFor(f.in, "owner-k8s-bootstrap-chain-10000000", f.profile.AuthMountAccessor, contracts.WorkerObjectReference{Name: f.pool.ServiceAccount, UID: f.pool.AccountUID}, f.profile.AuditCredentials, now)
	if err != nil {
		t.Fatal(err)
	}
	f.profile = ownerRecipe.Profile

	f.in.Public = &contracts.OwnerPublicDeployment{
		SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit-bootstrap-chain-10000000", Key: prefix + "-browser-sessions"},
		WorkSigning:    contracts.OwnerPublicSigning{Mount: "public-transit-bootstrap-chain-10000000", Name: prefix + "-work-signing"},
		WorkerPKI:      contracts.OwnerPublicWorkerPKI{Mount: "worker-pki-bootstrap-chain-10000000", Role: prefix + "-download-worker", IssuerEpoch: f.pool.IssuerEpoch},
		Fleet:          &contracts.OwnerFleetIssuance{ChannelMount: "fleet-bootstrap", DeliveryProfile: "regional-installer"},
	}
	_, digest, err := OwnerFleetProviderRecipeFor(f.in, f.profile, now)
	if err != nil {
		t.Fatal(err)
	}
	f.in.Public.Fleet.ProviderRecipeSHA256 = digest
	fed := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: f.in.InstallationID, ClusterID: f.in.ClusterID, PermissionRootID: f.in.PermissionRootID, AuditStore: f.in.AuditStore,
		KeyService: contracts.FederationKeyService{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, AuditMount: f.in.KeyService.AuditMount, AuditKey: prefix + "-federation-audit", PKIMount: "connector-pki-bootstrap-chain-10000000", ClientRole: prefix + "-connector-client", ServerRole: prefix + "-connector-server"}}
	recipe, err := FederationProviderRecipeFor(fed, contracts.FederationProviderAuthentication{AuthMount: f.profile.AuthMount, AuthMountAccessor: f.profile.AuthMountAccessor, Namespace: f.in.Namespace,
		ServiceAccount:   contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(f.in.InstallationID), UID: "10000000-0000-4000-8000-000000001492"},
		AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: "10000000-0000-4000-8000-000000001493"}})
	if err != nil {
		t.Fatal(err)
	}
	fed.ProviderAuthentication = &recipe.Profile
	publisher := publisherSetupFixture(t, f)
	publisher.Verifier.PKIMount = f.in.Public.WorkerPKI.Mount
	publisherRecipe, err := PublisherProviderRecipeFor(publisher, publisher.ProviderAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	publisher.ProviderAuthentication = publisherRecipe.Profile
	evidence := &contracts.InstallerEvidenceStore{Endpoint: publisher.Evidence.Endpoint, Region: publisher.Evidence.Region, Bucket: publisher.Evidence.Bucket}
	raw, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, now, &fed, &publisher, evidence, evidence, true)
	if err != nil {
		t.Fatal("complete promoted phase-3 recipe refused", err)
	}
	var sections map[string]json.RawMessage
	if json.Unmarshal(raw, &sections) != nil {
		t.Fatal("malformed recipe")
	}

	if string(sections["federation"]) != "true" {
		t.Fatal("federation selection marker missing")
	}
	base, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, now, nil, nil, evidence, evidence, true)
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		Apply   []ownerProviderSetupRequest `json:"apply"`
		Setup   json.RawMessage             `json:"setup"`
		Inspect []string                    `json:"inspect"`
	}
	var complete struct {
		Apply   []ownerProviderSetupRequest `json:"apply"`
		Setup   json.RawMessage             `json:"setup"`
		Inspect []string                    `json:"inspect"`
	}
	if json.Unmarshal(base, &original) != nil || json.Unmarshal(raw, &complete) != nil {
		t.Fatal("malformed apply recipe")
	}
	var baseFields map[string]json.RawMessage
	_ = json.Unmarshal(base, &baseFields)
	if _, present := baseFields["federation"]; present {
		t.Fatal("unselected federation marker emitted")
	}
	federationSetup, err := FederationProviderSetupFor(fed)
	if err != nil {
		t.Fatal(err)
	}
	federationRequests, err := federationSetup.requests(fed)
	if err != nil {
		t.Fatal(err)
	}
	publisherSection, publisherRequests, publisherPaths, err := publisherArtifactFor(f.in, &fed, publisher)
	if err != nil {
		t.Fatal(err)
	}
	expected := append(append(original.Apply, federationRequests...), publisherRequests...)
	wantApply, err := ownerProviderCanonical(expected)
	gotApply, gotErr := ownerProviderCanonical(complete.Apply)
	if err != nil || gotErr != nil || !bytes.Equal(gotApply, wantApply) {
		t.Fatal("complete apply changed a provider method/path/body")
	}
	if !bytes.Equal(complete.Setup, original.Setup) {
		t.Fatal("lost owner auth/reviewer prerequisites")
	}
	wantPublisher, err := ownerProviderCanonical(publisherSection)
	if err != nil || !bytes.Equal(sections["publisher"], wantPublisher) {
		t.Fatal("publisher operator instructions changed")
	}
	for _, name := range []string{"auditStorage", "downloadEvidenceReadStorage", "evidenceDeleteStorage", "operationCleanupStorage"} {
		if !bytes.Equal(sections[name], baseFields[name]) {
			t.Fatal("operator storage instructions changed", name)
		}
	}
	wantedPaths := map[string]int{}
	for _, path := range append(original.Inspect, federationSetupPaths(fed, federationSetup)...) {
		wantedPaths[path]++
	}
	for _, path := range publisherPaths {
		if wantedPaths[path] == 0 {
			wantedPaths[path] = 1
		}
	}
	for _, path := range complete.Inspect {
		if wantedPaths[path] == 0 {
			t.Fatal("unexpected inspection path", path)
		}
		wantedPaths[path]--
		if wantedPaths[path] == 0 {
			delete(wantedPaths, path)
		}
	}
	if len(wantedPaths) != 0 {
		t.Fatal("lost independent inspection paths", wantedPaths)
	}
	for name, value := range sections {
		t.Logf("section %s bytes=%d", name, len(value))
	}
	t.Logf("complete recipe bytes=%d limit=%d", len(raw), 64<<10)
	if len(raw) > 64<<10 {
		t.Fatal("recipe exceeds original artifact bound")
	}
	if f.requests.Load() != 0 {
		t.Fatal("artifact producer performed provider I/O")
	}
}
