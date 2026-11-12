package kubernetes

import (
	"bytes"
	"encoding/pem"
	"reflect"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/hashicorp/hcl"
)

type smallOpenBaoPrerequisiteData struct {
	TokenType  string            `hcl:"token_type"`
	Type       string            `hcl:"type"`
	Host       string            `hcl:"kubernetes_host"`
	CA         string            `hcl:"kubernetes_ca_cert"`
	Local      *bool             `hcl:"disable_local_ca_jwt"`
	Reviewer   string            `hcl:"token_reviewer_jwt"`
	Policy     string            `hcl:"policy"`
	Exportable *bool             `hcl:"exportable"`
	Backup     *bool             `hcl:"allow_plaintext_backup"`
	Allowed    []string          `hcl:"allowed_policies"`
	Orphan     bool              `hcl:"orphan"`
	Renewable  bool              `hcl:"renewable"`
	NoDefault  bool              `hcl:"token_no_default_policy"`
	MaxTTL     int               `hcl:"token_explicit_max_ttl"`
	Period     int               `hcl:"token_period"`
	Options    map[string]string `hcl:"options"`
	CommonName string            `hcl:"common_name"`
	TTL        string            `hcl:"ttl"`
	KeyType    string            `hcl:"key_type"`
	KeyBits    int               `hcl:"key_bits"`
}

func TestSmallOpenBaoPrerequisitesAreCompleteBeforeOriginalMarker(t *testing.T) {
	plan := smallOpenBaoFixturePlan(t, time.Now().UTC())
	backend := "00000000-0000-4000-8000-000000000001"
	config, err := SmallOpenBaoConfiguration(plan, backend)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Initialize []struct {
			Name     string `hcl:",key"`
			Requests []struct {
				Name      string                       `hcl:",key"`
				Operation string                       `hcl:"operation"`
				Path      string                       `hcl:"path"`
				Data      smallOpenBaoPrerequisiteData `hcl:"data"`
			} `hcl:"request,expand"`
		} `hcl:"initialize,expand"`
	}
	if err := hcl.Decode(&parsed, string(config)); err != nil {
		t.Fatal("generated initialization HCL cannot be decoded", err)
	}
	if len(parsed.Initialize) != 1 || parsed.Initialize[0].Name != "asservat" {
		t.Fatal("unexpected native initialization block")
	}
	requests := parsed.Initialize[0].Requests
	if len(requests) != 26 || requests[len(requests)-1].Name != "backend-identity" || requests[len(requests)-1].Path != contracts.SmallOpenBaoBackendPolicyPath {
		t.Fatal("prerequisites did not all precede original final marker", len(requests))
	}
	data := map[string]smallOpenBaoPrerequisiteData{}
	names := map[string]bool{}
	for _, request := range requests {
		if request.Operation != "update" || names[request.Name] {
			t.Fatal("duplicate/non-write initialization request")
		}
		names[request.Name] = true
		if _, exists := data[request.Path]; exists {
			t.Fatal("initialization unexpectedly rewrites a prerequisite")
		}
		data[request.Path] = request.Data
	}
	for _, mount := range []string{contracts.SmallOpenBaoSetupMount, contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount} {
		if data["sys/auth/"+mount].Type != "kubernetes" {
			t.Fatal("missing Kubernetes auth mount", mount)
		}
		d := data["auth/"+mount+"/config"]
		if d.Host != plan.Kubernetes.Endpoint || d.Local == nil || *d.Local || d.Reviewer != "" {
			t.Fatal("auth config escaped selected in-Pod reviewer")
		}
		var expected bytes.Buffer
		for _, der := range plan.Kubernetes.Roots {
			if pem.Encode(&expected, &pem.Block{Type: "CERTIFICATE", Bytes: der}) != nil {
				t.Fatal("fixture roots")
			}
		}
		if d.CA != expected.String() {
			t.Fatal("auth config lost pinned API roots")
		}
	}
	for _, mount := range []string{contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount} {
		if data["sys/mounts/"+mount].Type != "transit" {
			t.Fatal("missing exact transit mount")
		}
	}
	key := data[contracts.SmallOpenBaoAuditMount+"/keys/audit"]
	if key.Type != "aes256-gcm96" || key.Exportable == nil || *key.Exportable || key.Backup == nil || *key.Backup {
		t.Fatal("initial audit key is absent or exportable")
	}
	providers := contracts.SmallOpenBaoInitialProviders()
	policies, err := providerconfig.InitialProviderPolicyBodies(providers.IssuerPolicy, providers.WrapRole, providers.WrapPolicy, providers.UnwrapRole, providers.UnwrapPolicy, contracts.SmallOpenBaoAuditMount, "audit")
	if err != nil {
		t.Fatal(err)
	}
	for name, policy := range policies {
		if data["sys/policies/acl/"+name].Policy != policy {
			t.Fatal("initializer diverged from actual initial-audit policy", name)
		}
	}
	for _, role := range []struct{ name, policy string }{{providers.WrapRole, providers.WrapPolicy}, {providers.UnwrapRole, providers.UnwrapPolicy}, {contracts.SmallOpenBaoInitialIssuerRole, providers.IssuerPolicy}} {
		d := data["auth/token/roles/"+role.name]
		if !slices.Equal(d.Allowed, []string{role.policy}) || d.Orphan || d.Renewable || !d.NoDefault || d.TokenType != "service" || d.MaxTTL != 900 || d.Period != 0 {
			t.Fatal("initial role widened or lost finite child semantics", role.name)
		}
	}
	for _, mount := range []string{contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount} {
		d := data[mount+"/root/generate/internal"]
		if data["sys/mounts/"+mount].Type != "pki" || d.CommonName != plan.ServiceName()+" "+mount || d.TTL != "87600h" || d.KeyType != "ec" || d.KeyBits != 256 {
			t.Fatal("missing bounded exact internal issuer", mount)
		}
	}
	kv := data["sys/mounts/"+contracts.SmallOpenBaoBootstrapMount]
	if kv.Type != "kv" || !reflect.DeepEqual(kv.Options, map[string]string{"version": "2"}) {
		t.Fatal("fleet bootstrap KV is not exact version2")
	}
	marker, err := SmallOpenBaoBackendPolicy(backend)
	if err != nil || data[contracts.SmallOpenBaoBackendPolicyPath].Policy != marker {
		t.Fatal("final marker is not original backend")
	}
}
