package kubernetes

import (
	"asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestRetentionTopologyRequiresIndependentExactImmutablePin(t *testing.T) {
	for _, mode := range []string{"hub-local", "hub-only-explicit", "missing-local", "wrong-local-cluster", "duplicate-source", "missing-hub", "wrong-root", "wrong-content-pin", "replaced-object", "replaced-namespace", "mutable", "extra-data", "unknown", "case-alias", "zero-digest", "bad-hex", "expired", "different-target", "missing-object"} {
		t.Run(mode, func(t *testing.T) {
			b, err := os.ReadFile("../../../examples/retention-topology.json")
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if json.Unmarshal(b, &wire) != nil {
				t.Fatal("fixture")
			}
			root, target := wire["authorityRootID"].(string), wire["targetClusterID"].(string)
			switch mode {
			case "hub-only-explicit":
				wire["local"] = nil
			case "missing-local":
				delete(wire, "local")
			case "wrong-local-cluster":
				wire["local"].(map[string]any)["clusterID"] = wire["hub"].(map[string]any)["clusterID"]
			case "duplicate-source":
				wire["local"] = wire["hub"]
				wire["targetClusterID"] = wire["hub"].(map[string]any)["clusterID"]
				target = wire["targetClusterID"].(string)
			case "missing-hub":
				delete(wire, "hub")
			case "wrong-root":
				wire["authorityRootID"] = target
			case "unknown":
				wire["skipLocalCheck"] = true
			case "case-alias":
				wire["Local"] = wire["local"]
				delete(wire, "local")
			case "zero-digest":
				wire["local"].(map[string]any)["protectionSHA256"] = strings.Repeat("0", 64)
			case "bad-hex":
				wire["local"].(map[string]any)["protectionSHA256"] = strings.Repeat("g", 64)
			}
			b, _ = json.Marshal(wire)
			canonical := jsontext.Value(b)
			if err = canonical.Canonicalize(); err != nil {
				t.Fatal(err)
			}
			pin := artifact.Digest(sha256.Sum256(canonical))
			if mode == "wrong-content-pin" {
				pin[0]++
			}
			data := map[string]string{"topology.json": string(b)}
			if mode == "extra-data" {
				data["other"] = "data"
			}
			uid := "topology-uid"
			if mode == "replaced-object" {
				uid = "replacement"
			}
			var clock *atomic.Int64
			var unavailable atomic.Bool
			requests := atomic.Int64{}
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				requests.Add(1)
				if mode == "replaced-namespace" && r.URL.Path == "/api/v1/namespaces/asservat-system" {
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": permissionControl.Name, "uid": "replaced", "resourceVersion": "1"}})
					return true
				}
				if r.URL.Path != "/api/v1/namespaces/asservat-system/configmaps/topology" {
					return false
				}
				if unavailable.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				if mode == "missing-object" {
					w.WriteHeader(http.StatusNotFound)
					return true
				}
				if mode == "expired" {
					clock.Add(int64(5 * time.Second))
				}
				permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "topology", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "1"}, "immutable": mode != "mutable", "data": data})
				return true
			})
			clock = f.clock
			reader, err := NewRetentionTopologyClient(f.client, "topology", "topology-uid", root, target, pin)
			if err != nil {
				t.Fatal(err)
			}
			query := target
			if mode == "different-target" {
				query = root
			}
			out, err := reader.RetentionTopology(context.Background(), query)
			if mode == "hub-local" || mode == "hub-only-explicit" {
				want := 2
				if mode == "hub-only-explicit" {
					want = 1
				}
				if err != nil || !out.Valid(time.Unix(0, clock.Load())) || out.Revision.Digest != pin || out.RootID != root || out.TargetClusterID != target || len(out.Sources) != want || !out.Sources[0].Hub || out.FreshUntil.Sub(out.ObservedAt) != privacy.PolicyTopologyInterval {
					t.Fatal("valid topology", out, err)
				}
				// The pinned immutable read is reused within its interval.
				before := requests.Load()
				if again, err := reader.RetentionTopology(context.Background(), query); err != nil || again.Revision != out.Revision || requests.Load() != before {
					t.Fatal("pinned topology reread inside its interval", err, requests.Load()-before)
				}
			} else if err == nil {
				t.Fatal("unsafe topology accepted", mode)
			}
			if mode == "different-target" && requests.Load() != 0 {
				t.Fatal("caller selected a different configuration")
			}
			if mode == "hub-local" {
				// Installed native86: the observation is re-read on demand
				// once less than one evidence-read window remains, so a read
				// is not cut by it; a failed early re-read keeps it.
				clock.Store(out.FreshUntil.Add(-identity.EvidenceReadRequestWindow + time.Second).UnixNano())
				unavailable.Store(true)
				before := requests.Load()
				kept, err := reader.RetentionTopology(context.Background(), query)
				if err != nil || !kept.FreshUntil.Equal(out.FreshUntil) || requests.Load() == before {
					t.Fatal("failed early re-read dropped the still-current topology", err)
				}
				unavailable.Store(false)
				fresh, err := reader.RetentionTopology(context.Background(), query)
				if err != nil || fresh.FreshUntil.Sub(time.Unix(0, clock.Load())) < identity.EvidenceReadRequestWindow {
					t.Fatal("topology near its end was not re-read", err)
				}
				pins := []RetentionTopologyPin{{TargetClusterID: target, Name: "topology", UID: "topology-uid", ContentDigest: pin}}
				router, err := NewRetentionTopologies(f.client, root, pins)
				if err != nil {
					t.Fatal(err)
				}
				pins[0].TargetClusterID = root // caller mutation cannot change installed routing
				pins[0].ContentDigest = artifact.Digest{99}
				if got, err := router.RetentionTopology(context.Background(), target); err != nil || len(got.Sources) != 2 {
					t.Fatal("route lost local policy source", err)
				}
				before = requests.Load()
				if _, err := router.RetentionTopology(context.Background(), root); err == nil || requests.Load() != before {
					t.Fatal("unknown cluster fell back to another source")
				}
				if _, err := NewRetentionTopologies(f.client, root, append(pins, pins[0])); err == nil {
					t.Fatal("duplicate target/name accepted")
				}
			}
		})
	}
}
