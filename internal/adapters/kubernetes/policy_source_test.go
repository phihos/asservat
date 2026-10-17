package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"sigs.k8s.io/yaml"
)

func TestPolicySourceBoundedObservationAndIntent(t *testing.T) {
	read := func(mode string) (value.PolicySource, error) {
		t.Helper()
		y, e := os.ReadFile("../../../examples/policy-deployment.yaml")
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
		m["uid"] = "policy-uid"
		m["generation"] = 1
		m["resourceVersion"] = "opaque:policy"
		o["status"] = map[string]any{"phase": "Ready", "accepted": true, "executor": "forged-admin"}
		s := o["spec"].(map[string]any)
		switch mode {
		case "paused":
			s["suspended"] = true
		case "grant":
			s["grantRef"] = "11111111-1111-4111-8111-111111111119"
		case "explicit-no-save":
			s["recordingSaves"] = map[string]any{"enabled": false}
		case "save-enabled":
			s["recordingSaves"] = map[string]any{"enabled": true}
		case "threshold":
			s["detectors"].([]any)[1].(map[string]any)["options"].(map[string]any)["threshold"] = 0.86
		case "wrong-namespace":
			s["target"].(map[string]any)["namespace"] = "other"
		case "replacement":
			m["uid"] = "replacement"
		case "wrong-kind":
			o["kind"] = "DebugCapture"
		case "unknown":
			s["unsafeCommand"] = "forged"
		case "deleting":
			m["deletionTimestamp"] = "2026-10-10T11:59:59Z"
		case "bad-generation":
			m["generation"] = 1.5
		}
		var clock *atomic.Int64
		f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
			if mode == "namespace-replaced" && r.URL.Path == "/api/v1/namespaces/payments" {
				permissionReply(w, permissionNamespace("payments", "replacement"))
				return true
			}
			if r.URL.Path != "/apis/asservat.io/v1alpha1/namespaces/payments/debugpolicies/suspicious-api" {
				return false
			}
			if mode == "stale" {
				clock.Add(int64(5 * time.Second))
			}
			if mode == "missing" {
				http.NotFound(w, r)
				return true
			}
			permissionReply(w, o)
			return true
		})
		clock = f.clock
		c, e := NewPolicySourceClient(f.client, permissionCluster, cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, "suspicious-api", "policy-uid")
		if e != nil {
			t.Fatal(e)
		}
		return c.PolicySource(context.Background())
	}
	base, e := read("valid")
	if e != nil {
		t.Fatal(e)
	}
	if base.Suspended || base.Deleted || base.Revision.UID != "policy-uid" || base.FreshUntil.Sub(base.ObservedAt) != 5*time.Second {
		t.Fatal("source identity/status handling")
	}
	for _, mode := range []string{"paused", "grant", "explicit-no-save"} {
		t.Run(mode, func(t *testing.T) {
			got, e := read(mode)
			if e != nil || got.CollectionDigest != base.CollectionDigest || got.Revision.Digest == base.Revision.Digest {
				t.Fatalf("control edit changed collection intent: %v", e)
			}
		})
	}
	got, e := read("threshold")
	if e != nil || got.CollectionDigest == base.CollectionDigest {
		t.Fatal("fractional threshold edit lost")
	}
	got, e = read("deleting")
	if e != nil || !got.Deleted {
		t.Fatal("deletion metadata lost")
	}
	for _, mode := range []string{"wrong-namespace", "replacement", "namespace-replaced", "wrong-kind", "unknown", "bad-generation", "stale", "missing"} {
		t.Run(mode, func(t *testing.T) {
			if _, e := read(mode); e == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}

func TestPolicyJSONRejectsAmbiguityAndUnboundedNumbers(t *testing.T) {
	for _, s := range []string{`{"x":1,"x":2}`, `{"x":9007199254740993}`, `{"x":1e999}`, `{"x":NaN}`, `{} {}`, strings.Repeat("[", 33) + strings.Repeat("]", 33), "{\"x\":\"\xff\"}"} {
		if policyJSON([]byte(s), 4096) == nil {
			t.Fatalf("unsafe JSON accepted: %q", s)
		}
	}
	if policyJSON([]byte(`{"threshold":0.85}`), 4096) != nil {
		t.Fatal("resource ratio rejected")
	}
	if policyJSON([]byte(`{"threshold":0.85}`), 1) == nil {
		t.Fatal("byte ceiling ignored")
	}
}
