package bootstrap

import (
	"context"
	"os"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func regionalTestDeployment(t *testing.T) contracts.RegionalDeployment {
	t.Helper()
	f, _, l := newRuntimeFixture(t)
	l.Close()
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	roots := [][]byte{f.ca.Raw}
	guard := func(name string) contracts.OwnerDeploymentGuard {
		return contracts.OwnerDeploymentGuard{Name: name, PolicyUID: id("20"), PolicyGeneration: 1, BindingUID: id("21"), BindingResourceVersion: "1", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "installer"}}}
	}
	ref := func(name, n string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: id(n)}
	}
	c := contracts.RegionalDeployment{Format: contracts.RegionalDeploymentFormat, InstallationID: id("01"), ClusterID: id("02"), PermissionRootID: id("03"), IssuerEpoch: id("04"), PeerID: id("05"),
		Namespace: ref("asservat-connector", "06"), Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid", Roots: roots}, Deployment: ref("connector", "07"),
		WorkloadGuard: guard("connector-guard"), Source: ref("connector-identity", "08"), SourceGuard: guard("connector-source"), ClusterCredential: ref("cluster-credential", "09"), ClusterCredentialAccount: "connector",
		Hub: contracts.RegionalHubEndpoint{Endpoint: "https://federation.synthetic.invalid", ServerName: "federation.synthetic.invalid", Roots: roots}}
	c.APIContext = &contracts.RegionalAPIContext{Settings: "api-settings", SettingsGuard: guard("api-settings"),
		Starts:    contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: ref("capacity", "11"), ExecutionAccount: ref("connector", "12"), CapacityAudience: "https://kubernetes.default.svc"},
		WorkTrust: ref("work-trust", "13"), WorkTrustGuard: guard("work-trust"), TrustSettings: contracts.APIContextWorkTrustSettings{ClusterID: c.ClusterID},
		EvidenceStore: contracts.RegionalEvidenceStore{Endpoint: "https://evidence.synthetic.invalid", Roots: roots, Region: "local", Bucket: "evidence", StoreID: id("14")},
		KeyService:    contracts.RegionalWrapService{Endpoint: "https://keys.synthetic.invalid", Roots: roots, KeyID: "artifact-key"},
		Owners: contracts.RegionalContextOwners{Address: "hub.synthetic.invalid:9444", Configuration: contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: c.InstallationID, ClusterID: id("30"), IssuerEpoch: c.IssuerEpoch, Revision: 1,
			Namespace: ref("asservat-hub", "31"), Service: ref("hub-api", "32"), Deployment: ref("hub-api", "33"), ServiceAccount: ref("hub-api", "34"), Port: 9443, NativePort: 9444, IssuerRoots: roots}},
		Concurrency: 1}
	return c
}

// The optional ADR-171 regional context input is validated as a whole before
// any client is built; an invalid section stops the process.
func TestRegionalDeploymentAPIContextInputsAreClosed(t *testing.T) {
	read := func(c contracts.RegionalDeployment) error {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "regional.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readRegionalDeployment(context.Background(), root)
		return err
	}
	valid := regionalTestDeployment(t)
	if err := read(valid); err != nil {
		t.Fatal("valid regional context input", err)
	}
	without := valid
	without.APIContext = nil
	if err := read(without); err != nil {
		t.Fatal("credential-only regional input", err)
	}
	for name, mutate := range map[string]func(*contracts.RegionalAPIContext){
		"no concurrency":            func(a *contracts.RegionalAPIContext) { a.Concurrency = 0 },
		"plain HTTP evidence store": func(a *contracts.RegionalAPIContext) { a.EvidenceStore.Endpoint = "http://evidence.synthetic.invalid" },
		"store not a UUID":          func(a *contracts.RegionalAPIContext) { a.EvidenceStore.StoreID = "evidence" },
		"unsafe key ID":             func(a *contracts.RegionalAPIContext) { a.KeyService.KeyID = "../decrypt" },
		"address without port":      func(a *contracts.RegionalAPIContext) { a.Owners.Address = "hub.synthetic.invalid" },
		"owner pool without native": func(a *contracts.RegionalAPIContext) { a.Owners.Configuration.NativePort = 0 },
		"another installation": func(a *contracts.RegionalAPIContext) {
			a.Owners.Configuration.InstallationID = "10000000-0000-4000-8000-0000000000ff"
		},
		"no owner roots": func(a *contracts.RegionalAPIContext) { a.Owners.Configuration.IssuerRoots = nil },
		// The settings are read by name at start; the execution protection
		// checks their cluster (ADR-196 decision 7).
		"no settings name": func(a *contracts.RegionalAPIContext) { a.Settings = "" },
		"trust of another cluster": func(a *contracts.RegionalAPIContext) {
			a.TrustSettings.ClusterID = "10000000-0000-4000-8000-0000000000ff"
		},
		"guard without administrators": func(a *contracts.RegionalAPIContext) { a.WorkTrustGuard.Administrators = nil },
		"invalid capacity account":     func(a *contracts.RegionalAPIContext) { a.Starts.CapacityAccount.Name = "Capacity_Account" },
		"no capacity audience":         func(a *contracts.RegionalAPIContext) { a.Starts.CapacityAudience = "" },
	} {
		c := regionalTestDeployment(t)
		mutate(c.APIContext)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
}
