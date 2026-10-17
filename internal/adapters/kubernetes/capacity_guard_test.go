package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// Loopback protocol qualification with explicit synthetic API authority. Actual
// Kubernetes type-check/admission enforcement is a separate required native test.
func TestCapacityGuardsRequireExactIndependentCurrentDenial(t *testing.T) {
	for _, namespace := range []bool{false, true} {
		kind := "source"
		if namespace {
			kind = "namespace"
		}
		for _, mode := range []string{"valid", "probe-admin", "wrong-probe", "probe-status", "wrong-account", "rbac-denied", "admission-allows", "wrong-cause", "wrong-resource", "warn-only", "not-typechecked", "guard-change", "namespace-change", "account-change", "expired"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				admins := []cfg.KubernetesActor{{Kind: "Group", Name: "capacity-administrators"}}
				account := cfg.NamespaceRef{Name: "capacity-probe", UID: "probe-account-uid"}
				plan := cfg.CapacityAdministration{Name: "capacity-guard", ControlNamespace: permissionControl, Administrators: admins, StatusUsers: []string{"status-writer"}, ProbeAccount: account}
				nplan := cfg.CapacityNamespaceAdministration{Name: plan.Name, Administrators: admins, Keys: []string{"team"}, ProbeNamespace: permissionControl, ProbeAccount: account}
				p, b, err := CapacityAdmission(plan)
				if namespace {
					p, b, err = CapacityNamespaceAdmission(nplan)
				}
				if err != nil {
					t.Fatal(err)
				}
				p.UID, p.Generation, p.ResourceVersion = "policy", 1, "one"
				p.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{}}
				b.UID, b.ResourceVersion = "binding", "one"
				if mode == "warn-only" {
					b.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
				}
				if mode == "not-typechecked" {
					p.Status.TypeChecking = nil
				}
				pin := GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "one"}
				clock := &atomic.Int64{}
				clock.Store(time.Now().UTC().UnixNano())
				var probes atomic.Int64
				var changed atomic.Bool
				validator, err := newCapacityValidator()
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer synthetic-capacity-test" {
						t.Error("wrong synthetic probe credential")
					}
					switch {
					case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
						response := p.DeepCopy()
						if changed.Load() && mode == "guard-change" {
							response.ResourceVersion = "two"
						}
						permissionReply(w, response)
					case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
						permissionReply(w, b)
					case strings.HasSuffix(r.URL.Path, "/serviceaccounts/"+account.Name):
						uid := account.UID
						if mode == "wrong-account" || changed.Load() && mode == "account-change" {
							uid = "replacement"
						}
						permissionReply(w, core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Namespace: permissionControl.Name, Name: account.Name, UID: types.UID(uid)}})
					case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
						who := authentication.UserInfo{Username: "system:serviceaccount:" + permissionControl.Name + ":" + account.Name, UID: account.UID, Groups: []string{"authenticated"}}
						if mode == "probe-admin" {
							who.Groups = append(who.Groups, "capacity-administrators")
						}
						if mode == "wrong-probe" {
							who.Username = "other-probe"
						}
						if mode == "probe-status" {
							who.Username = "status-writer"
						}
						permissionReply(w, authentication.SelfSubjectReview{Status: authentication.SelfSubjectReviewStatus{UserInfo: who}})
					case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
						var request authorization.SelfSubjectAccessReview
						if json.NewDecoder(r.Body).Decode(&request) != nil {
							t.Error("SSAR body")
						}
						a := request.Spec.ResourceAttributes
						if a == nil || namespace && (a.Verb != "update" || a.Resource != "namespaces" || a.Name != permissionControl.Name || a.Namespace != "") || !namespace && (a.Verb != "create" || a.Group != "asservat.io" || a.Namespace != permissionControl.Name) {
							t.Error("probe uses unexpected RBAC authority")
						}
						permissionReply(w, authorization.SelfSubjectAccessReview{Status: authorization.SubjectAccessReviewStatus{Allowed: mode != "rbac-denied"}})
					case r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name:
						uid := permissionControl.UID
						if changed.Load() && mode == "namespace-change" {
							uid = "replacement"
						}
						permissionReply(w, core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: permissionControl.Name, UID: types.UID(uid), ResourceVersion: "ns:one", Labels: map[string]string{"team": "one", "unrelated": "keep"}}})
					default:
						if r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" {
							t.Error("probe was not strictly nonpersistent")
						}
						var body map[string]json.RawMessage
						if json.NewDecoder(r.Body).Decode(&body) != nil {
							t.Error("probe JSON")
						}
						resource, message, group := "evidencestoragepools", capacitySourceDenial, "asservat.io"
						if namespace {
							resource, message, group = "namespaces", capacityNamespaceDenial, ""
							if r.Method != "PUT" || r.URL.Path != "/api/v1/namespaces/"+permissionControl.Name {
								t.Error("namespace probe not exact named update")
							}
							var m meta.ObjectMeta
							if json.Unmarshal(body["metadata"], &m) != nil || string(m.UID) != permissionControl.UID || m.ResourceVersion != "ns:one" || m.Labels["team"] == "one" || m.Labels["unrelated"] != "keep" {
								t.Error("namespace probe lost identity or changed unrelated labels")
							}
						} else {
							if r.Method != "POST" {
								t.Error("source probe not create")
							}
							schema := validator.pool
							if strings.HasSuffix(r.URL.Path, "/evidencebudgetpolicies") {
								resource = "evidencebudgetpolicies"
								schema = validator.policy
							}
							var spec any
							if json.Unmarshal(body["spec"], &spec) != nil || schema.Validate(spec) != nil {
								t.Error("schema-invalid denial probe")
							}
						}
						probes.Add(1)
						changed.Store(true)
						if mode == "admission-allows" {
							permissionReply(w, body)
							return
						}
						if mode == "expired" {
							clock.Add(int64(6 * time.Second))
						}
						cause := "ValidatingAdmissionPolicy 'capacity-guard' with binding 'capacity-guard' denied request: " + message
						if mode == "wrong-cause" {
							cause = "denied by another policy"
						}
						if mode == "wrong-resource" {
							resource = "configmaps"
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(422)
						permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Group: group, Kind: resource, Causes: []meta.StatusCause{{Message: cause}}}})
					}
				}))
				t.Cleanup(server.Close)
				config := &rest.Config{Host: server.URL, BearerToken: "synthetic-capacity-test", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
				now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
				observer, err := NewPermissionClient(config, permissionCluster, permissionControl, now)
				if err != nil {
					t.Fatal(err)
				}
				probe, err := NewPermissionClient(config, permissionCluster, permissionControl, now)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				var until time.Time
				if namespace {
					g, e := NewCapacityNamespaceGuard(observer, probe, nplan, pin)
					if e != nil {
						t.Fatal(e)
					}
					v, e := g.CapacityNamespaceProtection(ctx)
					err = e
					until = v.FreshUntil
					if err == nil && (!v.Valid(now()) || len(v.Keys) != 1 || v.Keys[0] != "team") {
						t.Fatal("invalid protection output")
					}
				} else {
					g, e := NewCapacityGuard(observer, probe, plan, pin)
					if e != nil {
						t.Fatal(e)
					}
					v, e := g.CapacityProtection(ctx)
					err = e
					until = v.FreshUntil
					if err == nil && !v.Valid(now()) {
						t.Fatal("invalid protection output")
					}
				}
				if mode == "valid" {
					want := int64(2)
					if namespace {
						want = 1
					}
					if err != nil || probes.Load() != want || !until.Equal(deadline) {
						t.Fatalf("current guard/caller bound: %v, probes=%d until=%s", err, probes.Load(), until)
					}
				} else if err == nil {
					t.Fatal("invalid guard accepted")
				}
				if strings.HasPrefix(mode, "probe-") || mode == "wrong-probe" || mode == "wrong-account" || mode == "rbac-denied" {
					if probes.Load() != 0 {
						t.Fatal("unqualified probe reached mutation")
					}
				}
			})
		}
	}
}
