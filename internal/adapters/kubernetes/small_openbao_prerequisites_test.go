package kubernetes

import (
	"bytes"
	"encoding/pem"
	"testing"
	"time"

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
	if len(requests) != 5 || requests[len(requests)-1].Name != "backend-identity" || requests[len(requests)-1].Path != contracts.SmallOpenBaoBackendPolicyPath {
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
	for _, mount := range []string{contracts.SmallOpenBaoSetupMount} {
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
	if data["sys/policies/acl/"+contracts.SmallOpenBaoSetupPolicy].Policy != SmallOpenBaoSetupPolicy(plan.Name) {
		t.Fatal("setup policy diverged")
	}
	if len(data) != 5 {
		t.Fatal("self-initialization does more than the setup login and marker")
	}
	marker, err := SmallOpenBaoBackendPolicy(backend)
	if err != nil || data[contracts.SmallOpenBaoBackendPolicyPath].Policy != marker {
		t.Fatal("final marker is not original backend")
	}
}
