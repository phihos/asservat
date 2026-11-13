package bootstrap

import (
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialPreparerSelectsOnlyOriginalBundledIssuer(t *testing.T) {
	at := time.Now().UTC()
	id := func(n string) string { return "10000000-0000-4000-8000-00000000000" + n }
	selected := contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: "install", Namespace: contracts.WorkerObjectReference{Name: "trusted-bootstrap", UID: id("1")}, SetupAccount: contracts.WorkerObjectReference{Name: "install-setup", UID: id("2")}, EntityID: id("3"), SetupParent: contracts.InitialProviderParent{Accessor: "original-parent", IssuedAt: at, ExpiresAt: at.Add(300 * time.Second)}}
	c := contracts.InitialPreparer{Plan: contracts.InitialPreparationPlan{InstallationID: id("4"), RequestID: id("5"), BootstrapNamespace: selected.Namespace, RootName: "install-preparation"}, Services: &contracts.InitialPreparationServices{KeyService: contracts.ConfigurationKeyService{Endpoint: selected.Endpoint(), AuditMount: "asservat-audit", AuditKey: "audit"}}, Providers: &contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "install-material", UID: id("6")}, IssuerPolicy: "issuer", WrapRole: "wrap", WrapPolicy: "encrypt", UnwrapRole: "unwrap", UnwrapPolicy: "decrypt"}}
	material := contracts.InitialProviderMaterial{IssuerToken: "synthetic-original-issuer", BundledIdentity: &selected}
	client, err := initialPreparerIssuer(c, material, &http.Client{}, func() time.Time { return at })
	if err != nil {
		t.Fatal("retained selected identity refused", err)
	}
	client.Close()
	for _, name := range []string{"namespace-uid", "backend", "endpoint", "expired", "malformed"} {
		t.Run(name, func(t *testing.T) {
			next := selected
			v := c
			services := *c.Services
			v.Services = &services
			now := at
			switch name {
			case "namespace-uid":
				next.Namespace.UID = id("7")
			case "backend":
				next.BackendName = "other"
				next.SetupAccount.Name = "other-bootstrap-runner"
			case "endpoint":
				v.Services.KeyService.Endpoint = "https://other.invalid"
			case "expired":
				now = next.SetupParent.ExpiresAt
			case "malformed":
				next.EntityID = "invalid"
			}
			m := material
			m.BundledIdentity = &next
			got, err := initialPreparerIssuer(v, m, &http.Client{}, func() time.Time { return now })
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("foreign, expired or malformed selected identity accepted")
			}
		})
	}
	material.BundledIdentity = nil
	client, err = initialPreparerIssuer(c, material, &http.Client{}, func() time.Time { return at })
	if err != nil {
		t.Fatal("external profile changed", err)
	}
	client.Close()
}
