package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func mixedOwnerMaterialFixture(t *testing.T, bundledIdentity bool) (*continuationMaterialFixture, []byte) {
	t.Helper()
	f := newContinuationMaterialFixture(t, bundledIdentity)
	owner, _, _ := ownerSeaweedFixture(t, true)
	artifact, err := withInstallerServingTLSRecipe(owner.Artifact, contracts.InstallerServingTLSPlan{FederationServerName: "federation.example", KeyServiceServerName: "keys.example"})
	if err != nil {
		t.Fatal(err)
	}
	for key, credential := range map[string]contracts.SeaweedCredential{
		contracts.InstallerInboxAuditCredential: owner.Credentials.Owner, contracts.InstallerInboxFederationAuditCredential: owner.Credentials.Federation,
		contracts.InstallerInboxPublisherAuditCredential: owner.Credentials.PublisherAudit, contracts.InstallerInboxEvidenceReadCredential: owner.Credentials.PublisherRead,
		contracts.InstallerInboxDownloadEvidenceCredential: owner.Credentials.DownloadRead, contracts.InstallerInboxEvidenceDeleteCredential: owner.Credentials.EvidenceDelete,
		contracts.InstallerInboxCleanupAuditCredential: owner.Credentials.Cleanup, contracts.InstallerInboxCleanupVerifyCredential: owner.Credentials.Verify,
	} {
		value, e := providerconfig.SeaweedRuntimeCredential(credential)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(value)
		f.secrets["operator-material"].Data[key] = raw
	}
	return f, artifact
}
func TestMixedBundledKeyServiceUsesOriginalStorageAndIdentityMaterial(t *testing.T) {
	for _, bundledIdentity := range []bool{false, true} {
		t.Run(map[bool]string{false: "external-identity", true: "bundled-identity"}[bundledIdentity], func(t *testing.T) {
			f, artifact := mixedOwnerMaterialFixture(t, bundledIdentity)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			before, _ := json.Marshal(f.secrets["operator-material"])
			data, err := f.k.mixedExternalStorageData(ctx, 3, artifact)
			if err != nil {
				t.Fatal(err)
			}
			defer clearMixedInstallerData(data)
			if !bytes.Equal(data[contracts.InstallerInboxAuditCredential], f.secrets["operator-material"].Data[contracts.InstallerInboxAuditCredential]) || len(data[contracts.InstallerInboxInspectionToken]) != 0 || len(data["seal.key"]) != 0 || len(data["ca.key"]) != 0 {
				t.Fatal("external storage source changed or unrelated provider key escaped")
			}
			expected := f.secrets["operator-material"].Data[contracts.OwnerPublicClientSecretFile]
			if bundledIdentity {
				expected = f.secrets["trial-keycloak-state"].Data[contracts.SmallKeycloakConsoleSecret]
			}
			if !bytes.Equal(data[contracts.OwnerPublicClientSecretFile], expected) {
				t.Fatal("original selected identity's client secret replaced")
			}
			after, _ := json.Marshal(f.secrets["operator-material"])
			expectedCalls := 1
			if bundledIdentity {
				expectedCalls++
			}
			if !bytes.Equal(before, after) || f.calls != expectedCalls {
				t.Fatal("material source mutated or observed twice", f.calls)
			}
		})
	}
}
func TestMixedExternalStorageRequiresExactPhaseInput(t *testing.T) {
	for _, mode := range []string{"missing-source", "bad-source-name", "missing-worker", "valid-worker", "missing-owner", "missing-federation", "unused-credential"} {
		t.Run(mode, func(t *testing.T) {
			f, artifact := mixedOwnerMaterialFixture(t, false)
			phase := 3
			switch mode {
			case "missing-source":
				f.k.input.MaterialSecretName = ""
			case "bad-source-name":
				f.k.input.MaterialSecretName = "../foreign"
			case "missing-worker":
				phase = 1
			case "valid-worker":
				phase = 1
				f.secrets["operator-material"].Data[contracts.ConfigurationProviderAuditCredentialFile] = bytes.Clone(f.secrets["operator-material"].Data[contracts.InstallerInboxAuditCredential])
			case "missing-owner":
				delete(f.secrets["operator-material"].Data, contracts.InstallerInboxAuditCredential)
			case "missing-federation":
				delete(f.secrets["operator-material"].Data, contracts.InstallerInboxFederationAuditCredential)
			case "unused-credential":
				var a map[string]json.RawMessage
				_ = json.Unmarshal(artifact, &a)
				delete(a, "federation")
				artifact, _ = json.Marshal(a)
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			data, err := f.k.mixedExternalStorageData(ctx, phase, artifact)
			if mode == "valid-worker" {
				if err != nil || len(data) != 2 || !bytes.Equal(data[contracts.InstallerInboxAuditCredential], f.secrets["operator-material"].Data[contracts.ConfigurationProviderAuditCredentialFile]) {
					t.Fatal("phase1 worker selected the owner's key", err)
				}
				clearMixedInstallerData(data)
				return
			}
			if err == nil || data != nil {
				clearMixedInstallerData(data)
				t.Fatal("missing/unselected external material accepted")
			}
			if (mode == "missing-source" || mode == "bad-source-name") && f.calls != 0 {
				t.Fatal("invalid named source reached API")
			}
		})
	}
}
func TestMixedProviderKnownChangedCarrierFailsWithoutPolling(t *testing.T) {
	f := newContinuationMaterialFixture(t, false)
	installation := "10000000-0000-4000-8000-000000000001"
	f.k.record.Scope.InstallationID = installation
	digest := installerRecipeDigest([]byte(`{"recipe":"original"}`))
	credential, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "ASV0011223344556677889900112233445566778899", SecretAccessKey: "0011223344556677889900112233445566778899001122334455667788990011"})
	f.secrets[contracts.InstallerInboxName(installation)] = &core.Secret{TypeMeta: meta.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: meta.ObjectMeta{Name: contracts.InstallerInboxName(installation), Namespace: "bootstrap", UID: types.UID(initialBaoState), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "bundled-installer-inbox"}, Annotations: map[string]string{"asservat.io/provider-recipe-sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "asservat.io/provider-mode": contracts.InstallerProviderBundledObjectStore}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.InstallerInboxPhase: []byte("1"), contracts.InstallerInboxAuditCredential: credential}}
	ctx, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	if _, err := f.k.awaitMixedProviderData(ctx, 1, digest, contracts.InstallerProviderBundledObjectStore, true); !errors.Is(err, cfg.ErrChanged) || f.calls != 1 {
		t.Fatal("known changed carrier treated as transient wait", err, f.calls)
	}
}
