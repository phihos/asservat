package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

func identitySettingsFixture(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../../examples/identity-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("fixture")
	}
	return v
}
func TestIdentityPolicyPinnedConfigAndCurrentRevocation(t *testing.T) {
	var reply atomic.Value
	var reads atomic.Int64
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/identity.settings" {
			return false
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reply.Load().([]byte))
		return true
	})
	settings := identitySettingsFixture(t)
	set := func(v map[string]any, uid string) {
		t.Helper()
		b, _ := json.Marshal(v)
		object := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "identity.settings", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "policy-rv"}, "data": map[string]string{"identity.json": string(b)}}
		encoded, _ := json.Marshal(object)
		reply.Store(encoded)
	}
	set(settings, "identity-uid")
	reader, err := NewIdentityPolicyClient(f.client, "identity.settings", "identity-uid", "https://id.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := reader.IdentityPolicy(context.Background(), "https://id.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Revision.UID != "identity-uid" || policy.FreshUntil.Sub(policy.ObservedAt) != 30*time.Second || len(policy.Clients) != 2 {
		t.Fatal("policy identity/bounds lost")
	}
	now := time.Unix(0, f.clock.Load()).UTC()
	claims := identity.Claims{Issuer: policy.Issuer, Subject: "developer", ClientID: "asservat-console", Groups: []string{"platform-developers"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), KeyUntil: now.Add(time.Minute)}
	if _, err = identity.Admit(claims, policy, now); err != nil {
		t.Fatal(err)
	}
	settings["eligibleGroups"] = []string{"another-team"}
	settings["revision"] = 2
	set(settings, "identity-uid")
	changed, err := reader.IdentityPolicy(context.Background(), claims.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = identity.Admit(claims, changed, now); !errors.Is(err, identity.ErrDenied) {
		t.Fatal("removed group retained eligibility")
	}
	if changed.Revision.Digest == policy.Revision.Digest {
		t.Fatal("configuration digest unchanged")
	}
	before := reads.Load()
	if _, err = reader.IdentityPolicy(context.Background(), "https://attacker.invalid"); !errors.Is(err, identity.ErrDenied) || before != reads.Load() {
		t.Fatal("untrusted issuer selected installation lookup")
	}
	set(settings, "replacement")
	if _, err = reader.IdentityPolicy(context.Background(), claims.Issuer); err == nil {
		t.Fatal("replaced ConfigMap trusted")
	}
}
func TestIdentityPolicyRejectsMalformedAndUnqualifiedSettings(t *testing.T) {
	for _, mode := range []string{"unknown", "case-alias", "duplicate-client", "unqualified-client", "unqualified-groups", "empty-eligible", "overlong-age", "control-character", "wrong-issuer", "null-groups", "duplicate-json", "oversize", "binary-data", "wrong-namespace", "deleting", "expired-io", "clock-rollback"} {
		t.Run(mode, func(t *testing.T) {
			settings := identitySettingsFixture(t)
			switch mode {
			case "unknown":
				settings["administrator"] = true
			case "case-alias":
				settings["Issuer"] = settings["issuer"]
				delete(settings, "issuer")
			case "duplicate-client":
				settings["clients"] = []any{map[string]any{"id": "same", "kind": "human", "classQualified": true}, map[string]any{"id": "same", "kind": "workload", "classQualified": true}}
			case "unqualified-client":
				settings["clients"].([]any)[0].(map[string]any)["classQualified"] = false
			case "unqualified-groups":
				settings["groupsAtIssueQualified"] = false
			case "empty-eligible":
				settings["eligibleGroups"] = []string{}
			case "overlong-age":
				settings["groupMaxAgeSeconds"] = 301
			case "control-character":
				settings["eligibleGroups"] = []string{"bad\u0085group"}
			case "wrong-issuer":
				settings["issuer"] = "https://another.invalid"
			case "null-groups":
				settings["eligibleGroups"] = nil
			}
			body, _ := json.Marshal(settings)
			if mode == "duplicate-json" {
				body = []byte(strings.Replace(string(body), `"revision":1`, `"revision":1,"revision":2`, 1))
			}
			if mode == "oversize" {
				body = []byte(strings.Repeat(" ", 65537))
			}
			metadata := map[string]any{"name": "identity", "namespace": permissionControl.Name, "uid": "identity-uid", "resourceVersion": "rv"}
			if mode == "wrong-namespace" {
				metadata["namespace"] = "other"
			}
			if mode == "deleting" {
				metadata["deletionTimestamp"] = "2026-10-10T12:00:00Z"
			}
			object := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": map[string]string{"identity.json": string(body)}}
			if mode == "binary-data" {
				object["binaryData"] = map[string]string{"surprise": "AA=="}
			}
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/identity" {
					return false
				}
				if mode == "expired-io" {
					clock.Add(int64(5 * time.Second))
				}
				if mode == "clock-rollback" {
					clock.Add(-int64(time.Second))
				}
				permissionReply(w, object)
				return true
			})
			clock = f.clock
			reader, err := NewIdentityPolicyClient(f.client, "identity", "identity-uid", "https://id.example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reader.IdentityPolicy(context.Background(), "https://id.example.invalid"); err == nil {
				t.Fatal("unsafe settings accepted")
			}
		})
	}
}
