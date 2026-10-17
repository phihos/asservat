package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func ownerProviderInputFixture(t *testing.T) (*ownerInputs, string, contracts.OwnerDeployment) {
	t.Helper()
	in, dir, c := ownerInputFixture(t)
	a := ownerObservationTestActivation(c)
	a.Input.OwnerLayout = contracts.OwnerProviderInstalledLayout
	c.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: strings.Repeat("1", 64), ImageDigest: strings.Repeat("2", 64), ProtectionDigest: strings.Repeat("3", 64), Activation: a, Peers: []contracts.OwnerObservationPeer{{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: runtimeID, Roots: c.Kubernetes.Roots}}}
	secret := contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(c.InstallationID), UID: "66666666-6666-4666-8666-666666666666"}
	r, e := providerconfig.OwnerProviderRecipeFor(c, "owner-auth", "auth_kubernetes_original", a.Input.ServiceAccount, secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c.ProviderAuthentication = &r.Profile
	writeOwnerJSON(t, dir, "deployment.json", c)
	return in, dir, c
}

func TestProviderOwnerInputRequiresCompleteSelectedBranch(t *testing.T) {
	for _, mode := range []string{"valid", "missing-profile", "missing-observation", "missing-activation", "legacy-layout", "native-mixed", "changed-scope", "changed-recipe", "changed-secret-name"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := ownerProviderInputFixture(t)
			switch mode {
			case "missing-profile":
				c.ProviderAuthentication = nil
			case "missing-observation":
				c.Observation = nil
			case "missing-activation":
				c.Observation.Activation = nil
			case "legacy-layout":
				c.Observation.Activation.Input.OwnerLayout = contracts.OwnerInstalledLayout
			case "native-mixed":
				c.Native = &contracts.OwnerNativeDeployment{}
			case "changed-scope":
				c.ProviderAuthentication.ServiceAccount.UID = runtimeID
			case "changed-recipe":
				c.ProviderAuthentication.RecipeSHA256 = strings.Repeat("0", 64)
			case "changed-secret-name":
				c.ProviderAuthentication.AuditCredentials.Name += "-other"
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			got, err := readOwnerInputs(context.Background(), in.files)
			if mode == "valid" {
				if err != nil || got.config.ProviderAuthentication == nil || got.config.Observation.Activation.Input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
					t.Fatal("explicit provider branch rejected", err)
				}
				got.closeHTTP()
			} else if err == nil {
				got.closeHTTP()
				t.Fatal("mixed/unknown provider selection fell back to legacy")
			}
		})
	}
}

func TestProviderOwnerProjectionReadsOnlyFixedSQLFilesAndRejectsLegacyMaterial(t *testing.T) {
	in, dir, c := ownerProviderInputFixture(t)
	a := c.Observation.Activation
	m := contracts.OwnerIdentityCredentialManifest{Format: contracts.OwnerIdentityCredentialManifestFormat, Input: a.Input, RootUID: a.RoleRoot.UID, SetupID: a.RoleSetupID}
	writeOwnerJSON(t, dir, contracts.OwnerIdentityRoleManifestFile, m)
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		writeOwnerJSON(t, dir, "sql-"+purpose+".json", contracts.OwnerSQLCredential{Username: purpose, Password: "synthetic-component-credential"})
	}
	// A provider token file or audit payload is not needed to inspect the fixed
	// SQL projection. The independent native/provider checks follow this read.
	values, manifest, err := readSelectedOwnerIdentityProviders(context.Background(), in.files, c)
	if err != nil || len(values) != 1+len(contracts.OwnerIdentityRolePurposes()) || manifest.RootUID != m.RootUID {
		t.Fatal("fixed SQL-only projection unavailable", err)
	}
	for _, b := range values {
		clear(b)
	}
	for _, name := range []string{"audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token"} {
		path := filepath.Join(dir, name)
		if err = os.WriteFile(path, []byte("synthetic-legacy-material"), 0600); err != nil {
			t.Fatal(err)
		}
		if values, _, err = readSelectedOwnerIdentityProviders(context.Background(), in.files, c); err == nil {
			for _, b := range values {
				clear(b)
			}
			t.Fatal("selected branch silently accepted legacy credential", name)
		}
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	// A dangling old credential link is still a mixed projection, not absence.
	if err = os.Symlink("not-present", filepath.Join(dir, "audit-wrap.token")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readSelectedOwnerIdentityProviders(context.Background(), in.files, c); err == nil {
		t.Fatal("dangling legacy projection was treated as an omitted field")
	}
	encoded, err := json.Marshal(c)
	if err != nil || strings.Contains(string(encoded), "synthetic-component-credential") {
		t.Fatal("public provider input contains SQL credential")
	}
}

// ADR-182: an installed owner may be promoted with Native and Public. The
// public layer then has the fixed installed port and a pinned public provider
// recipe; the legacy layout never carries one.
func TestInstalledOwnerPromotionInputs(t *testing.T) {
	for _, mode := range []string{"backend", "public", "public-port", "public-no-recipe", "public-changed-pki", "public-no-projection", "public-other-projection", "public-empty-lists", "legacy-recipe"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := ownerProviderInputFixture(t)
			c.Native = &contracts.OwnerNativeDeployment{ConnectorRoots: c.Kubernetes.Roots, Connections: 2, Concurrency: 1,
				WorkerAPIs:          []contracts.OwnerNativeWorkerAPI{{ClusterID: c.ClusterID, Namespace: contracts.WorkerObjectReference{Name: "workers", UID: runtimeID}, Kubernetes: c.Kubernetes}},
				RetentionTopologies: []contracts.OwnerNativeTopology{{TargetClusterID: runtimeID, Name: "topology", UID: runtimeID, SHA256: strings.Repeat("1", 64)}}}
			if mode != "backend" {
				c.Public = &contracts.OwnerPublicDeployment{Format: contracts.OwnerPublicDeploymentFormat, Origin: "https://asservat.example.test",
					BrowserRootID: runtimeID, BrowserSettings: contracts.WorkerObjectReference{Name: "browser-settings", UID: runtimeID}, IdentitySettings: contracts.WorkerObjectReference{Name: "identity-settings", UID: runtimeID},
					BrowserAudience: "asservat-api", ProviderRoots: c.Kubernetes.Roots, SessionTransit: contracts.OwnerPublicTransit{Mount: "browser-transit", Key: "sessions"},
					WorkSigning: contracts.OwnerPublicSigning{Mount: "work-transit", Name: "work", Version: 1, PublicKey: make([]byte, 32), KeyID: "work"}, WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: runtimeID, Roots: c.Kubernetes.Roots},
					Port: contracts.OwnerInstalledPublicPort, Version: "v1", OperationConcurrency: 8, MCPPerIdentity: 2, DownloadConcurrency: 4, DownloadsPerIdentity: 2, DownloadMaxSeconds: 3600,
					RuntimeProjection: contracts.WorkerObjectReference{Name: contracts.PublicRuntimeProjectionName(c.InstallationID), UID: runtimeID}}
				_, digest, err := providerconfig.OwnerPublicProviderRecipeFor(c, *c.ProviderAuthentication, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				c.Public.ProviderRecipeSHA256 = digest
			}
			switch mode {
			case "public-port":
				c.Public.Port = 8443
			case "public-no-recipe":
				c.Public.ProviderRecipeSHA256 = ""
			case "public-changed-pki":
				c.Public.WorkerPKI.Role = "other"
			case "public-empty-lists":
				c.Native.WorkerAPIs, c.Native.RetentionTopologies = []contracts.OwnerNativeWorkerAPI{}, []contracts.OwnerNativeTopology{}
			case "public-no-projection":
				c.Public.RuntimeProjection = contracts.WorkerObjectReference{}
			case "public-other-projection":
				c.Public.RuntimeProjection.Name = "asservat-other-public"
			case "legacy-recipe":
				c.ProviderAuthentication, c.Observation = nil, nil
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			got, err := readOwnerInputs(context.Background(), in.files)
			if (mode == "backend" || mode == "public" || mode == "public-empty-lists") != (err == nil) {
				t.Fatal("promotion input decision", mode, err)
			}
			if err == nil {
				got.closeHTTP()
			}
		})
	}
}
