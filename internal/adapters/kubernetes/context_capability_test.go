package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func capabilityTestSettings() contracts.ContextCapabilitySettings {
	p := compiler.ProjectionDigest()
	return contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: ownerID(1), InstallationID: ownerID(2), ClusterID: permissionCluster, IssuerEpoch: ownerID(3), Revision: 1, Enabled: true, ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "synthetic-qualified-v1", CollectorImageDigest: strings.Repeat("1", 64), ProjectionDigest: hex.EncodeToString(p[:])}
}

func TestContextCapabilityExactImmutableSnapshot(t *testing.T) {
	for _, mode := range []string{"valid", "unknown", "duplicate", "trailing", "alias", "missing-enabled", "null-enabled", "disabled", "foreign-image", "foreign-epoch", "foreign-projection", "foreign-revision", "mutable", "replacement", "binary", "extra-key", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			installed := capabilityTestSettings()
			b, _ := json.Marshal(installed)
			var w map[string]any
			_ = json.Unmarshal(b, &w)
			switch mode {
			case "unknown":
				w["command"] = "forbidden"
			case "alias":
				w["Revision"] = w["revision"]
				delete(w, "revision")
			case "missing-enabled":
				delete(w, "enabled")
			case "null-enabled":
				w["enabled"] = nil
			case "disabled":
				w["enabled"] = false
			case "foreign-image":
				w["collectorImageDigest"] = strings.Repeat("2", 64)
			case "foreign-epoch":
				w["issuerEpoch"] = ownerID(9)
			case "foreign-projection":
				w["projectionDigest"] = strings.Repeat("2", 64)
			case "foreign-revision":
				w["revision"] = 2
			}
			b, _ = json.Marshal(w)
			raw := string(b)
			if mode == "duplicate" {
				raw = strings.Replace(raw, `"revision":1`, `"revision":1,"revision":1`, 1)
			}
			if mode == "trailing" {
				raw += `{}`
			}
			if mode == "oversize" {
				raw = strings.Repeat(" ", contracts.ContextCapabilityMaxBytes) + raw
			}
			var payload atomic.Value
			payload.Store(raw)
			f := newPermissionFixture(t, func(out http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/configmaps/context-capability") {
					return false
				}
				uid := ownerID(7)
				if mode == "replacement" {
					uid = ownerID(8)
				}
				data := map[string]string{"context-capability.json": payload.Load().(string)}
				if mode == "extra-key" {
					data["other"] = "{}"
				}
				obj := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": mode != "mutable", "metadata": map[string]any{"name": "context-capability", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "1"}, "data": data}
				if mode == "binary" {
					obj["binaryData"] = map[string]string{"private": "AQ=="}
				}
				permissionReply(out, obj)
				return true
			})
			s := &ContextCapabilitySource{client: f.client, name: "context-capability", uid: ownerID(7), installed: installed}
			got, err := s.snapshot(context.Background())
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid capability accepted")
				}
				return
			}
			if err != nil || got.Revision.UID != ownerID(7) || got.ExecutionClass != artifact.ContextAPIExecution {
				t.Fatal("qualified snapshot", err)
			}
			pretty, _ := json.MarshalIndent(installed, "", "  ")
			payload.Store(string(pretty))
			again, err := s.snapshot(context.Background())
			if err != nil || again != got {
				t.Fatal("formatting changed immutable qualification", err)
			}
		})
	}
}

type capabilityRecovery struct {
	clock *atomic.Int64
	mode  string
	calls int
}

func (r *capabilityRecovery) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	r.calls++
	now := time.Unix(0, r.clock.Load()).UTC()
	p := artifact.RecoveryProof{InstallationID: ownerID(2), IssuerEpoch: ownerID(3), Revision: identity.Revision{UID: ownerID(4), Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if r.mode == "wrong-epoch" {
		p.IssuerEpoch = ownerID(9)
	}
	if r.mode == "short-recovery" {
		p.FreshUntil = now.Add(time.Second)
	}
	if r.mode == "recovery-change" && r.calls > 1 {
		p.Revision.Generation++
	}
	return p, ctx.Err()
}

// Real loopback TLS and concrete protection/source adapters; recovery, server
// admission replies and clock are synthetic. This is not native VAP proof.
func TestContextCapabilityPreservesAllOriginalBounds(t *testing.T) {
	for _, mode := range []string{"valid", "hub-held", "wrong-target", "wrong-epoch", "wrong-policy", "wrong-denial", "probe-admin", "rbac-denied", "guard-changed", "source-changed", "expired-final-guard", "short-recovery", "recovery-change", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			installed := capabilityTestSettings()
			if mode == "hub-held" { // ADR-179: the hub's own cluster holds a workload cluster's capability
				installed.ClusterID = ownerID(10)
			}
			raw, _ := json.Marshal(installed)
			plan := cfg.ConfigMapAdministration{Name: "capability-guard", ControlNamespace: permissionControl, SourceName: "context-capability", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "admin"}}}
			p, b, err := ContextCapabilityAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			p.UID = "policy"
			p.Generation = 1
			p.ResourceVersion = "1"
			p.Status.ObservedGeneration = 1
			p.Status.TypeChecking = &admission.TypeChecking{}
			b.UID = "binding"
			b.ResourceVersion = "1"
			pin := GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "1"}
			clock := &atomic.Int64{}
			start := time.Now().UTC()
			clock.Store(start.UnixNano())
			probes := 0
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-only" {
					t.Error("wrong synthetic credential")
				}
				switch {
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
					obj := p.DeepCopy()
					if mode == "wrong-policy" {
						obj.UID = "other"
					}
					if mode == "guard-changed" && probes > 0 {
						obj.ResourceVersion = "2"
					}
					permissionReply(w, obj)
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
					permissionReply(w, b)
				case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
					user := "outsider"
					if mode == "probe-admin" {
						user = "admin"
					}
					permissionReply(w, authn.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authn.SelfSubjectReviewStatus{UserInfo: authn.UserInfo{Username: user, Groups: []string{"authenticated"}}}})
				case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
					permissionReply(w, authz.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: authz.SubjectAccessReviewStatus{Allowed: mode != "rbac-denied"}})
				case strings.HasSuffix(r.URL.Path, "/configmaps/context-capability"):
					if r.Method == "PUT" {
						probes++
						if r.URL.Query().Get("dryRun") != "All" {
							t.Error("persistent probe")
						}
						cause := "ValidatingAdmissionPolicy 'capability-guard' with binding 'capability-guard' denied request: " + contextCapabilityDenial
						if mode == "wrong-denial" {
							cause = "unrelated denial"
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(422)
						permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: cause}}}})
						if probes == 2 && mode == "expired-final-guard" {
							clock.Add(int64(6 * time.Second))
						}
						if probes == 2 && mode == "short-recovery" {
							clock.Add(int64(2 * time.Second))
						}
						return
					}
					reads++
					uid := ownerID(7)
					if mode == "source-changed" && reads >= 3 {
						uid = ownerID(8)
					}
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": true, "metadata": map[string]any{"name": "context-capability", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "1"}, "data": map[string]string{"context-capability.json": string(raw)}})
				case r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name:
					permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
				default:
					t.Error("unexpected API path")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			observer, err := NewPermissionClient(config, permissionCluster, permissionControl, now)
			if err != nil {
				t.Fatal(err)
			}
			probe, err := NewPermissionClient(config, permissionCluster, permissionControl, now)
			if err != nil {
				t.Fatal(err)
			}
			guard, err := NewContextCapabilityProtection(observer, probe, plan, pin)
			if err != nil {
				t.Fatal(err)
			}
			recovery := &capabilityRecovery{clock: clock, mode: mode}
			s, err := NewContextCapabilitySource(observer, guard, recovery, "context-capability", ownerID(7), installed)
			if err != nil {
				t.Fatal(err)
			}
			target := authorization.Target{ClusterID: installed.ClusterID, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}
			if mode == "wrong-target" {
				target.ClusterID = ownerID(9)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got, err := s.ContextCapability(ctx, target)
			if mode != "valid" && mode != "hub-held" {
				if err == nil {
					t.Fatal("unavailable qualification accepted")
				}
				return
			}
			if err != nil || !got.Valid(now()) || !got.ObservedAt.Equal(start) || !got.FreshUntil.Equal(start.Add(5*time.Second)) || probes != 2 {
				t.Fatal("capability lost original observation", err, probes)
			}
		})
	}
}
