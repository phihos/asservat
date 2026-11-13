package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

// The hub-worker's source protections observe only the control namespace
// under ordinary RBAC: no admission policy read, no probe identity and no
// dry-run proof (helm-native-install plan, slice 0). The fixture rejects every
// non-GET request and every path except the namespace.
func TestSourceGuardsObserveNamespaceWithoutAdmissionPolicy(t *testing.T) {
	pin := GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "one"}
	admins := []value.KubernetesActor{{Kind: "Group", Name: "administrators"}}
	permissionPlan := value.PermissionAdministration{Name: "permission-guard", ControlNamespace: permissionControl, Administrators: admins}
	retentionPlan := value.RetentionAdministration{Name: "retention-guard", ControlNamespace: permissionControl, Administrators: admins, StatusUsers: []string{"status"}, Delegations: []value.RetentionDelegation{{Writers: []value.KubernetesActor{{Kind: "User", Name: "delegate"}}, Scope: privacy.PolicyScope{ClusterIDs: []string{permissionCluster}}}}}
	capacityPlan := value.CapacityAdministration{Name: "capacity-guard", ControlNamespace: permissionControl, Administrators: admins, StatusUsers: []string{"status"}, ProbeAccount: value.NamespaceRef{Name: "probe", UID: "probe-uid"}}
	namespacePlan := value.CapacityNamespaceAdministration{Name: "capacity-ns-guard", Administrators: admins, Keys: []string{"team"}, ProbeNamespace: permissionControl, ProbeAccount: value.NamespaceRef{Name: "probe", UID: "probe-uid"}}
	workloadPlan := value.WorkloadAdministration{Name: "workload-guard", Administrators: admins, LabelKeys: []string{"team"}, ProbeNamespace: permissionControl, ProbeAccount: value.NamespaceRef{Name: "probe", UID: "probe-uid"}}

	// The digests persisted in SQL keep their original inputs.
	digest := func(v any) artifact.Digest {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(b)
	}
	// The capacity digests name the cluster and observed namespace only.
	capacityDigest := func(any) artifact.Digest {
		return namedDigest("asservat-capacity-protection/v2", permissionCluster, permissionControl.Name)
	}
	wantPermission := digest(struct {
		ClusterID string
		Plan      value.PermissionAdministration
		Pin       GuardPin
	}{permissionCluster, permissionPlan, pin})
	wantRetention, err := RetentionGuardDigest(permissionCluster, retentionPlan, pin)
	if err != nil {
		t.Fatal(err)
	}

	type observation struct {
		digest     artifact.Digest
		start, end time.Time
	}
	readers := map[string]func(*PermissionClient) (observation, error){
		"permission": func(c *PermissionClient) (observation, error) {
			g, err := NewPermissionGuard(c, permissionPlan, pin)
			if err != nil {
				t.Fatal(err)
			}
			p, err := g.PermissionTrust(context.Background())
			return observation{p.Digest, p.ObservedAt, p.FreshUntil}, err
		},
		"retention": func(c *PermissionClient) (observation, error) {
			g, err := NewRetentionGuard(c, retentionPlan, pin)
			if err != nil {
				t.Fatal(err)
			}
			p, err := g.RetentionProtection(context.Background())
			if err == nil && (p.SourceClusterID != permissionCluster || p.ControlNamespaceUID != permissionControl.UID || p.Digest != g.Digest()) {
				t.Fatal("retention source identity")
			}
			return observation{p.Digest, p.ObservedAt, p.FreshUntil}, err
		},
		"capacity": func(c *PermissionClient) (observation, error) {
			g, err := NewCapacityGuard(c, capacityPlan, pin)
			if err != nil {
				t.Fatal(err)
			}
			p, err := g.CapacityProtection(context.Background())
			if err == nil && (p.ClusterID != permissionCluster || p.ControlNamespaceUID != permissionControl.UID) {
				t.Fatal("capacity source identity")
			}
			return observation{p.Digest, p.ObservedAt, p.FreshUntil}, err
		},
		"capacity-namespace": func(c *PermissionClient) (observation, error) {
			g, err := NewCapacityNamespaceGuard(c, namespacePlan, pin)
			if err != nil {
				t.Fatal(err)
			}
			p, err := g.CapacityNamespaceProtection(context.Background())
			if err == nil && (p.ClusterID != permissionCluster || len(p.Keys) != 1 || p.Keys[0] != "team") {
				t.Fatal("namespace guard keys")
			}
			return observation{p.Digest, p.ObservedAt, p.FreshUntil}, err
		},
		"workload": func(c *PermissionClient) (observation, error) {
			g, err := NewWorkloadGuard(c, workloadPlan, pin)
			if err != nil {
				t.Fatal(err)
			}
			p, err := g.WorkloadGuardProof(context.Background())
			if err == nil && (p.ClusterID != permissionCluster || p.Name != WorkloadGuardProfile || len(p.LabelKeys) != 1 || p.LabelKeys[0] != "team") {
				t.Fatal("workload guard keys")
			}
			return observation{artifact.Digest{}, p.ObservedAt, p.FreshUntil}, err
		},
	}
	want := map[string]artifact.Digest{"permission": wantPermission, "retention": wantRetention, "capacity": capacityDigest(capacityPlan), "capacity-namespace": capacityDigest(namespacePlan)}

	for name, read := range readers {
		for _, mode := range []string{"current", "replaced", "terminating", "unavailable", "expired"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				var f permissionFixture
				f = newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
					if strings.Contains(r.URL.Path, "admissionregistration") || strings.Contains(r.URL.Path, "selfsubject") {
						t.Error("admission guard machinery was used")
					}
					if r.URL.Path != "/api/v1/namespaces/"+permissionControl.Name {
						return false
					}
					ns := permissionNamespace(permissionControl.Name, permissionControl.UID)
					switch mode {
					case "replaced":
						ns = permissionNamespace(permissionControl.Name, "replacement")
					case "terminating":
						ns["metadata"].(map[string]any)["deletionTimestamp"] = "2026-10-10T12:00:00Z"
					case "unavailable":
						http.Error(w, "synthetic", http.StatusServiceUnavailable)
						return true
					case "expired":
						f.clock.Add(int64(6 * time.Second))
					}
					permissionReply(w, ns)
					return true
				})
				// Capacity observations bound their reads by the client clock.
				f.clock.Store(time.Now().UTC().UnixNano())
				started := time.Unix(0, f.clock.Load()).UTC()
				got, err := read(f.client)
				switch mode {
				case "current":
					if err != nil {
						t.Fatal(err)
					}
					if !got.start.Equal(started) || got.end.Sub(got.start) != 5*time.Second {
						t.Fatalf("observation window %v-%v", got.start, got.end)
					}
					if d, ok := want[name]; ok && got.digest != d {
						t.Fatal("protection digest changed")
					}
				case "replaced", "terminating", "unavailable":
					if !errors.Is(err, value.ErrChanged) {
						t.Fatalf("%s: %v", mode, err)
					}
				case "expired":
					if err == nil {
						t.Fatal("expired observation accepted")
					}
				}
			})
		}
	}
}
