package kubernetes

import (
	"encoding/json"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestSmallOpenBaoSetupSudoOnlyTwoExactAuthMounts(t *testing.T) {
	var policy struct {
		Path map[string]struct {
			Capabilities []string `json:"capabilities"`
		} `json:"path"`
	}
	if json.Unmarshal([]byte(smallOpenBaoSetupPolicy()), &policy) != nil {
		t.Fatal("invalid policy")
	}
	exact := map[string]bool{"sys/auth/" + contracts.SmallOpenBaoConfigurationAuthMount: false, "sys/auth/" + contracts.SmallOpenBaoOwnerAuthMount: false}
	for path, rule := range policy.Path {
		if slices.Contains(rule.Capabilities, "delete") {
			t.Fatal("setup gained delete")
		}
		if slices.Contains(rule.Capabilities, "sudo") {
			if _, ok := exact[path]; !ok {
				t.Fatal("sudo outside exact two auth mounts")
			}
			if !slices.Equal(rule.Capabilities, []string{"create", "read", "update", "sudo"}) {
				t.Fatal("auth mount capability changed")
			}
			exact[path] = true
		}
	}
	for _, found := range exact {
		if !found {
			t.Fatal("missing exact auth administration")
		}
	}
	for _, path := range []string{"sys/auth/*", "sys/auth/asservat-*", "sys/auth/asservat-configuration/tune", "sys/auth/asservat-owner/tune", "sys/auth/asservat-setup", "sys/raw/*", "auth/token/create"} {
		if _, ok := policy.Path[path]; ok {
			t.Fatal("broader administration path")
		}
	}
}

func TestSmallOpenBaoSetupMountsMatchBundledConsumers(t *testing.T) {
	var policy struct {
		Path map[string]struct {
			Capabilities []string `json:"capabilities"`
		} `json:"path"`
	}
	if err := json.Unmarshal([]byte(smallOpenBaoSetupPolicy()), &policy); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{"asservat-audit", "public-transit", "owner-pki", "connector-pki", "worker-pki", "fleet-bootstrap"} {
		if !slices.Equal(policy.Path["sys/mounts/"+mount].Capabilities, []string{"create", "read", "update"}) {
			t.Fatal("bundled consumer mount unavailable", mount)
		}
	}
	for _, mount := range []string{"asservat-audit", "public-transit"} {
		if !slices.Equal(policy.Path[mount+"/keys/*"].Capabilities, []string{"create", "read", "update"}) {
			t.Fatal("distinct audit/public key preparation unavailable")
		}
	}
	for _, old := range []string{"transit", "pki-owner", "pki-connector", "pki-worker", "bootstrap"} {
		if _, ok := policy.Path["sys/mounts/"+old]; ok {
			t.Fatal("unconsumed draft mount remains")
		}
	}
	if contracts.SmallOpenBaoAuditMount == contracts.SmallOpenBaoTransitMount {
		t.Fatal("audit and session/work mounts must remain distinct")
	}
}
