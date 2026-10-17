package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigurationProviderProfileIsClosedPublicInput(t *testing.T) {
	p := ConfigurationProviderAuthentication{Format: ConfigurationProviderAuthenticationFormat, AuthMount: "configuration-auth", AuthMountAccessor: "auth_kubernetes_original",
		ServiceAccount:   WorkerObjectReference{Name: "worker", UID: "10000000-0000-4000-8000-000000000001"},
		AuditCredentials: WorkerObjectReference{Name: "worker-providers", UID: "10000000-0000-4000-8000-000000000002"}, RecipeSHA256: strings.Repeat("a", 64)}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeConfigurationProviderAuthentication(bytes.NewReader(b))
	if err != nil || got != p {
		t.Fatal("closed original profile failed", err)
	}
	for _, field := range []string{`"token":"private"`, `"reviewer":"private"`, `"role":"chosen"`, `"tokenTTL":100000`, `"providerAdministrator":true`, `"authMount":"duplicate"`} {
		t.Run(field, func(t *testing.T) {
			bad := append(append([]byte{}, b[:len(b)-1]...), []byte(","+field+"}")...)
			if _, e := DecodeConfigurationProviderAuthentication(bytes.NewReader(bad)); e == nil {
				t.Fatal("extra authority/duplicate accepted")
			}
		})
	}
	bad := bytes.Replace(b, []byte(`"authMount"`), []byte(`"AuthMount"`), 1)
	if _, e := DecodeConfigurationProviderAuthentication(bytes.NewReader(bad)); e == nil {
		t.Fatal("field alias accepted")
	}
	if ConfigurationProviderAudience("installation", "cluster") == OwnerProviderAudience("installation", "cluster") {
		t.Fatal("worker can use owner provider audience")
	}
}
