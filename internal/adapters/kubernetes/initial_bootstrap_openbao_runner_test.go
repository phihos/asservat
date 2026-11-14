package kubernetes

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

// The fixed public selection is available wherever desired input is resolved;
// only producer/continuation own the provider setup token. No whole state Secret
// (seal key, CA private key, root credential) enters any installer compartment.
func assertOpenBaoRunnerCompartments(t *testing.T, pod *core.Pod, continuation bool) {
	t.Helper()
	public, tokens := map[string]bool{}, map[string]bool{}
	for _, v := range pod.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, source := range v.Projected.Sources {
			if source.Secret != nil && source.Secret.Name == "install-openbao-state" {
				public[v.Name] = true
				expected := map[string]string{contracts.SmallOpenBaoPlanKey: contracts.InitialBootstrapKeyServicePlanFile, "ca.crt": contracts.InitialBootstrapKeyServiceCAFile, contracts.SmallOpenBaoBackendKey: contracts.InitialBootstrapKeyServiceBackendFile}
				if len(source.Secret.Items) != len(expected) || source.Secret.Optional == nil || *source.Secret.Optional {
					t.Fatal("OpenBao public projection broadened or optional")
				}
				for _, item := range source.Secret.Items {
					if expected[item.Key] != item.Path {
						t.Fatal("private/foreign OpenBao key projected")
					}
					delete(expected, item.Key)
				}
				if len(expected) != 0 {
					t.Fatal("missing OpenBao public input")
				}
			}
			if token := source.ServiceAccountToken; token != nil && token.Path == contracts.InitialBootstrapKeyServiceTokenFile {
				tokens[v.Name] = true
				if token.Audience != contracts.SmallOpenBaoSetupAudience || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 {
					t.Fatal("provider setup token scope changed")
				}
			}
		}
	}
	if !public["producer-input"] || !public["retirement-input"] || public["continuation-input"] != continuation || len(public) != 2+boolCount(continuation) || !tokens["producer-input"] || tokens["retirement-input"] || tokens["continuation-input"] != continuation || len(tokens) != 1+boolCount(continuation) {
		t.Fatal("provider public/token compartment mismatch")
	}
}
func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}
