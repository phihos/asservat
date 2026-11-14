package kubernetes

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func initialRegistryFixture(t *testing.T) []byte {
	t.Helper()
	b, e := providerconfig.NormalizeInitialRegistry(initialWorkloadPlan().Image, []byte(`{"auths":{"registry.invalid":{"username":"fixture","password":"synthetic-only"}}}`))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func initialProjectionFiles() map[string][]byte {
	files := map[string][]byte{}
	for _, key := range []string{"sql-prepare.json", "sql-audit.json", "sql-activate.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "kube-probe.token"} {
		files[key] = []byte("synthetic-only")
	}
	return files
}

func TestInitialRegistryMaterialSharesOriginalEnvelopeBudget(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	d.Image = initialWorkloadPlan().Image
	d.RegistryAuthentication = contracts.InitialRegistryAuthentication
	m := *s.Material
	m.RegistryConfig = initialRegistryFixture(t)
	if !bootstrapRegistryMaterialValid(d, m) {
		t.Fatal("bounded material denied")
	}
	// Maxima must not add independent unaccounted envelopes. The wire's base64
	// expansion is included before any seed or downstream provider effect.
	m.IssuerToken = strings.Repeat("t", 1024)
	m.Storage.AccessKeyID = strings.Repeat("a", 256)
	m.Storage.SecretAccessKey = strings.Repeat("s", 1024)
	m.Storage.SessionToken = strings.Repeat("x", 4096)
	config := []byte(`{"auths":{"registry.invalid":{"username":"user","password":"` + strings.Repeat("p", 2048) + `"}}}`)
	var e error
	m.RegistryConfig, e = providerconfig.NormalizeInitialRegistry(d.Image, config)
	if e != nil {
		t.Fatal(e)
	}
	if bootstrapRegistryMaterialValid(d, m) {
		t.Fatal("combined serialized input exceeded original 8 KiB backing")
	}
	// The exact final envelope boundary includes the two original UUIDs.
	m = *s.Material
	m.IssuerToken = strings.Repeat("t", 1024)
	m.Storage.AccessKeyID = strings.Repeat("a", 256)
	m.Storage.SecretAccessKey = strings.Repeat("s", 1024)
	m.RegistryConfig, e = providerconfig.NormalizeInitialRegistry(d.Image, config)
	if e != nil {
		t.Fatal(e)
	}
	last := -1
	for n := 0; n <= 4096; n++ {
		m.Storage.SessionToken = strings.Repeat("x", n)
		if bootstrapRegistryMaterialValid(d, m) {
			last = n
		} else {
			break
		}
	}
	if last < 0 || last == 4096 {
		t.Fatal("no bounded fixture accepted")
	}
	if last < 4096 {
		m.Storage.SessionToken = strings.Repeat("x", last+1)
		if bootstrapRegistryMaterialValid(d, m) {
			t.Fatal("serialized overflow accepted")
		}
	}
}
