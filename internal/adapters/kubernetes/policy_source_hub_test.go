package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	app "asservat.local/asservat/internal/application/capture"
	planning "asservat.local/asservat/internal/application/planning"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"sigs.k8s.io/yaml"
)

// ADR-228: a hub-held policy lives in the control namespace and targets a
// namespace of a workload cluster. Only the hub reader accepts it; the
// shipped example compiles to the accepted restart subset.
func TestHubHeldPolicySourceReadsTheControlNamespace(t *testing.T) {
	y, e := os.ReadFile("../../../examples/policy-restart.yaml")
	if e != nil {
		t.Fatal(e)
	}
	b, e := yaml.YAMLToJSON(y)
	if e != nil {
		t.Fatal(e)
	}
	var o map[string]any
	if json.Unmarshal(b, &o) != nil {
		t.Fatal("fixture")
	}
	m := o["metadata"].(map[string]any)
	m["uid"], m["generation"], m["resourceVersion"] = "policy-uid", 1, "opaque:policy"
	control := cfg.NamespaceRef{Name: "asservat-system", UID: "control-uid"}
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces/asservat-system":
			permissionReply(w, permissionNamespace("asservat-system", "control-uid"))
		case "/apis/asservat.io/v1alpha1/namespaces/asservat-system/debugpolicies/checkout-restarts":
			permissionReply(w, o)
		default:
			return false
		}
		return true
	})
	hub, e := NewHubPolicySources(f.client, permissionCluster, control)
	if e != nil {
		t.Fatal(e)
	}
	source, spec, e := hub.ReadPolicy(context.Background(), "checkout-restarts", "")
	if e != nil || source.NamespaceUID != "control-uid" || source.ClusterID != permissionCluster || source.Revision.UID != "policy-uid" {
		t.Fatal("hub-held source", source, e)
	}
	if _, _, e = hub.ReadPolicy(context.Background(), "checkout-restarts", "other-uid"); e == nil {
		t.Fatal("pinned read accepted a replacement UID")
	}
	compiled, e := app.CompileRestartPolicy(spec, planning.ContextRecipeName, planning.RecipeDigest())
	if e != nil || compiled.ClusterID != "00000000-0000-4000-8000-000000000001" || compiled.Namespace != "payments" || compiled.WorkloadName != "checkout" {
		t.Fatal("example does not compile", compiled, e)
	}
	colocated, e := NewPolicySourceClient(f.client, permissionCluster, control, "checkout-restarts", "policy-uid")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = colocated.PolicySource(context.Background()); e == nil {
		t.Fatal("a co-located reader accepted a policy for another cluster")
	}
}
