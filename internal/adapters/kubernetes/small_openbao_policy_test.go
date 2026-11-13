package kubernetes

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func smallOpenBaoPolicyPaths(t *testing.T) map[string][]string {
	t.Helper()
	var policy struct {
		Path map[string]struct {
			Capabilities []string `json:"capabilities"`
		} `json:"path"`
	}
	if json.Unmarshal([]byte(SmallOpenBaoSetupPolicy("trial")), &policy) != nil {
		t.Fatal("invalid policy")
	}
	out := map[string][]string{}
	for path, rule := range policy.Path {
		out[path] = rule.Capabilities
	}
	return out
}

func TestSmallOpenBaoSetupSudoOnlyTwoExactAuthMounts(t *testing.T) {
	paths := smallOpenBaoPolicyPaths(t)
	sudo := 0
	for path, capabilities := range paths {
		if slices.Contains(capabilities, "delete") {
			t.Fatal("setup gained delete", path)
		}
		if slices.Contains(capabilities, "sudo") {
			if path != "sys/auth/"+contracts.SmallOpenBaoConfigurationAuthMount && path != "sys/auth/"+contracts.SmallOpenBaoOwnerAuthMount {
				t.Fatal("sudo outside the two component auth mounts", path)
			}
			sudo++
		}
	}
	if sudo != 2 {
		t.Fatal("missing auth mount administration")
	}
	for _, path := range []string{"sys/auth/*", "sys/auth/" + contracts.SmallOpenBaoSetupMount, "sys/raw/*", "auth/token/create", "auth/token/create/*", "sys/policies/acl/*", "sys/policies/acl/trial-*", "sys/policies/acl/" + contracts.SmallOpenBaoSetupPolicy, contracts.SmallOpenBaoBackendPolicyPath} {
		if _, ok := paths[path]; ok {
			t.Fatal("broader administration path", path)
		}
	}
}

// The setup login cannot rewrite its own policy or the backend marker: the
// policy globs are per component.
func TestSmallOpenBaoSetupPoliciesArePerComponent(t *testing.T) {
	for path := range smallOpenBaoPolicyPaths(t) {
		if strings.HasPrefix(path, "sys/policies/acl/") && !slices.ContainsFunc([]string{"hub-api", "hub-worker", "federation", "publisher"}, func(c string) bool { return path == "sys/policies/acl/trial-"+c+"-*" }) {
			t.Fatal("policy path outside the component prefixes", path)
		}
	}
}

func TestSmallOpenBaoSetupMountsMatchBundledConsumers(t *testing.T) {
	paths := smallOpenBaoPolicyPaths(t)
	for _, mount := range []string{"asservat-audit", "public-transit", "owner-pki", "connector-pki", "worker-pki", "fleet-bootstrap"} {
		if !slices.Equal(paths["sys/mounts/"+mount], []string{"create", "read", "update"}) {
			t.Fatal("bundled consumer mount unavailable", mount)
		}
	}
	for _, mount := range []string{"asservat-audit", "public-transit"} {
		// Transit key creation is an update (no existence check); there is
		// still no delete, export or backup capability.
		if !slices.Equal(paths[mount+"/keys/*"], []string{"create", "read", "update"}) {
			t.Fatal("transit keys must be create/read/update only", mount)
		}
	}
	if _, ok := paths[contracts.SmallOpenBaoBootstrapMount+"/data/*"]; ok {
		t.Fatal("setup reads bootstrap channel data")
	}
}
