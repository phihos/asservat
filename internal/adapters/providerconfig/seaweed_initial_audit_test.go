package providerconfig

import (
	"bytes"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestReadSeaweedInitialAuditCredentialOnlyOriginalInstallation(t *testing.T) {
	admin := swCredential(t, "admin", swCluster) // Backend identity is not installation identity.
	initial := swCredential(t, "initial-audit", swInstall)
	owner := swCredential(t, "owner-audit", swInstall)
	complete, err := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{
		{Credential: initial, Bucket: "audit", InstallationID: swInstall},
		{Credential: owner, Bucket: "audit", InstallationID: swInstall, RootID: swRoot, Prefixes: []string{"hub-owner-enrollment/v1/" + swInstall + "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(complete.Config)
	got, err := ReadSeaweedInitialAuditCredential(complete.Config, swInstall)
	if err != nil || got != initial {
		t.Fatal("did not recover exact retained initial key")
	}
	if _, err := ReadSeaweedInitialAuditCredential(complete.Config, swCluster); err == nil {
		t.Fatal("selected backend/foreign identity")
	}
	if _, err := ReadSeaweedInitialAuditCredential(complete.Config, ""); err == nil {
		t.Fatal("accepted missing original installation")
	}
}

func TestReadSeaweedInitialAuditCredentialRefusesMissingOrInvalidIAM(t *testing.T) {
	admin := swCredential(t, "admin", swCluster)
	initial := swCredential(t, "initial-audit", swInstall)
	original, err := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: initial, Bucket: "audit", InstallationID: swInstall}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original.Config)
	empty, err := CompileSeaweedStorage(admin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(empty.Config)
	for name, raw := range map[string][]byte{
		"missing":           empty.Config,
		"invalid-key":       bytes.Replace(original.Config, []byte(initial.SecretAccessKey), []byte("invalid"), 1),
		"invalid-other-key": bytes.Replace(original.Config, []byte(admin.AccessKeyID), []byte("invalid"), 1),
		"foreign-field":     bytes.Replace(original.Config, []byte(`"actions":`), []byte(`"foreign":`), 1),
		"trailing":          append(bytes.Clone(original.Config), []byte(` {}`)...),
		"empty":             nil,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ReadSeaweedInitialAuditCredential(raw, swInstall)
			if err == nil || got != (contracts.SeaweedCredential{}) {
				t.Fatal("invalid retained configuration produced credential")
			}
		})
	}
}
