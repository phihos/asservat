package bootstrap

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Losing the pending phase-3 carrier is an operator restoration problem, not
// permission to rotate an already enabled key. The actual complete-set compiler
// can produce the same public policy for a new candidate, but the retained IAM
// transition must still refuse it before any provider configuration update.
func TestSeaweedOwnerInboxLostCarrierCannotRotateEnabledKey(t *testing.T) {
	original, admin, initial := ownerSeaweedFixture(t, true)
	enabled, _, err := compileOwnerSeaweedFixture(original, admin, initial)
	if err != nil {
		t.Fatal("actual original full recipe refused", err)
	}
	defer clear(enabled.Config)
	originalBytes := bytes.Clone(enabled.Config)
	defer clear(originalBytes)
	// The first activation preserves both earlier principals and adds only the
	// eight selected phase-3 principals; an exact full replay remains permitted.
	phase1, err := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{initial, original.Worker})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(phase1.Config)
	if providerconfig.ValidateSeaweedConfigTransition(phase1.Config, enabled.Config) != nil {
		t.Fatal("first complete-set expansion lost retained initial/worker keys")
	}
	runtime, err := providerconfig.SeaweedRuntimeCredential(original.Credentials.Owner)
	if err != nil {
		t.Fatal(err)
	}
	storedWire, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(storedWire)
	// Recover ONLY the acknowledged carrier's original bytes, regardless of a
	// fresh speculative candidate generated during an explicit process retry.
	candidateWire, err := newSeaweedInboxCredential("owner-audit", original.Owner.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(candidateWire)
	candidate, err := seaweedInboxCredential(candidateWire, "owner-audit", original.Owner.InstallationID)
	if err != nil || candidate == original.Credentials.Owner {
		t.Fatal("fresh candidate did not retain exact typed scope")
	}
	winner, err := seaweedInboxCredential(storedWire, "owner-audit", original.Owner.InstallationID)
	if err != nil || winner != original.Credentials.Owner {
		t.Fatal("retained winner was not recovered exactly")
	}
	replay := original
	replay.Credentials.Owner = winner
	replayed, _, err := compileOwnerSeaweedFixture(replay, admin, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(replayed.Config)
	if !bytes.Equal(replayed.Config, enabled.Config) || providerconfig.ValidateSeaweedConfigTransition(enabled.Config, replayed.Config) != nil {
		t.Fatal("original winner replay changed an enabled key")
	}
	lost := original
	lost.Credentials.Owner = candidate
	replacement, _, err := compileOwnerSeaweedFixture(lost, admin, initial)
	if err != nil {
		t.Fatal("new same-scope candidate must reach the actual retained transition guard", err)
	}
	defer clear(replacement.Config)
	if !reflect.DeepEqual(replacement.Policies, enabled.Policies) {
		t.Fatal("test changed recipe/policy instead of only private key")
	}
	if providerconfig.ValidateSeaweedConfigTransition(enabled.Config, replacement.Config) == nil {
		t.Fatal("lost carrier rotated an enabled principal")
	}
	if !bytes.Equal(enabled.Config, originalBytes) {
		t.Fatal("refused transition mutated original IAM")
	}
}

func TestSeaweedInboxCredentialUsesClosedWireAndCallerSelectedPrincipal(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	for _, purpose := range []string{"owner-audit", "federation-audit", "publisher-audit", "publisher-read", "download-read", "evidence-delete", "operation-cleanup", "operation-verify"} {
		t.Run(purpose, func(t *testing.T) {
			raw, err := newSeaweedInboxCredential(purpose, installation)
			if err != nil {
				t.Fatal("scoped generation refused", err)
			}
			defer clear(raw)
			c, err := seaweedInboxCredential(raw, purpose, installation)
			if err != nil || c.Principal != (contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: installation}) || providerconfig.ValidateSeaweedCredential(c) != nil {
				t.Fatal("wire recovery changed selected scope")
			}
			for _, bad := range [][]byte{
				bytes.Replace(raw, []byte(`"sessionToken":""`), []byte(`"sessionToken":"foreign"`), 1),
				append(bytes.Clone(raw), []byte(` {}`)...),
				bytes.Replace(raw, []byte(`"secretAccessKey":`), []byte(`"foreignKey":`), 1),
				bytes.Replace(raw, []byte(`"accessKeyID":"ASV`), []byte(`"accessKeyID":"invalid`), 1),
			} {
				got, err := seaweedInboxCredential(bad, purpose, installation)
				clear(bad)
				if err == nil || got != (contracts.SeaweedCredential{}) {
					t.Fatal("unclosed/foreign credential accepted")
				}
			}
			if _, err := seaweedInboxCredential(raw, purpose, "replacement"); err == nil {
				t.Fatal("invalid caller installation accepted")
			}
		})
	}
	for _, purpose := range []string{"admin", "unknown"} {
		if raw, err := newSeaweedInboxCredential(purpose, installation); err == nil || len(raw) != 0 {
			clear(raw)
			t.Fatal("unselected/admin runtime credential generated")
		}
	}
}
