package providerconfig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestSeaweedStorageCredentialHasNoAuthorityBeforeBinding(t *testing.T) {
	credential, err := GenerateSeaweedStorageCredential()
	if err != nil {
		t.Fatal(err)
	}
	if len(credential.AccessKeyID) != 43 || !strings.HasPrefix(credential.AccessKeyID, "ASV") || len(credential.SecretAccessKey) != 64 || credential.SessionToken != "" {
		t.Fatal("raw credential shape changed")
	}
	for _, encoded := range []string{credential.AccessKeyID[3:], credential.SecretAccessKey} {
		raw, err := hex.DecodeString(encoded)
		if err != nil || hex.EncodeToString(raw) != encoded {
			t.Fatal("noncanonical random credential encoding")
		}
		clear(raw)
	}
	// Random credential bytes alone cannot become a provider identity.
	bound := contracts.SeaweedCredential{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey}
	if ValidateSeaweedCredential(bound) == nil {
		t.Fatal("unbound credentials acquired a provider principal")
	}
	bound.Principal = contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: swInstall}
	if ValidateSeaweedCredential(bound) != nil {
		t.Fatal("actual retained installation scope refused")
	}
	if generated, err := GenerateSeaweedCredential(bound.Principal); err != nil || ValidateSeaweedCredential(generated) != nil {
		t.Fatal("typed generator no longer uses the supported credential format")
	}
	if _, err := GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit"}); err == nil {
		t.Fatal("typed generator accepted missing installation scope")
	}
}

func TestInitialBootstrapMaterialCanDecodeEmptyStorageBeforeGeneration(t *testing.T) {
	// The actual installer producer marshals the complete typed credential.
	// An omitted-field object is not the same canonical wire contract.
	missing := []byte(`{"format":"asservat-initial-bootstrap-material/v1","issuerToken":"synthetic-component-issuer","storage":{},"storageUseUntil":"2026-11-12T12:00:00Z"}`)
	if _, err := contracts.DecodeInitialBootstrapMaterial(bytes.NewReader(missing)); err == nil {
		t.Fatal("missing credential fields accepted")
	}
	raw, err := json.Marshal(contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: "synthetic-component-issuer", StorageUseUntil: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	material, err := contracts.DecodeInitialBootstrapMaterial(bytes.NewReader(raw))
	if err != nil || material.Storage != (contracts.OwnerStorageCredential{}) {
		t.Fatal("structural empty storage is not accepted", err)
	}
	credential, err := GenerateSeaweedStorageCredential()
	if err != nil {
		t.Fatal(err)
	}
	material.Storage = credential
	encoded, err := json.Marshal(material)
	if err != nil {
		t.Fatal("encode generated bootstrap material")
	}
	defer clear(encoded)
	decoded, err := contracts.DecodeInitialBootstrapMaterial(bytes.NewReader(encoded))
	if err != nil || decoded.Storage != credential {
		t.Fatal("original material does not preserve exact generated credential bytes", err)
	}
}
