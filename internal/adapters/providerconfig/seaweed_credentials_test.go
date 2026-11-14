package providerconfig

import (
	"encoding/hex"
	"strings"
	"testing"

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
