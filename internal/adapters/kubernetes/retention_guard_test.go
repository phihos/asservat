package kubernetes

import (
	value "asservat.local/asservat/internal/domain/configuration"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"encoding/pem"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetentionGuardCurrentEnforcementAndNegativeControls(t *testing.T) {
	for _, mode := range []string{"valid", "warn-only", "wrong-uid", "not-typechecked", "wrong-cause", "probe-admin", "probe-delegate", "probe-status", "rbac-denied", "admission-allows", "namespace-replaced", "changed-during-probe", "expired"} {
		t.Run(mode, func(t *testing.T) {
			plan := value.RetentionAdministration{Name: "retention-guard", ControlNamespace: permissionControl, Administrators: []value.KubernetesActor{{Kind: "User", Name: "admin"}}, StatusUsers: []string{"status"}, Delegations: []value.RetentionDelegation{{Writers: []value.KubernetesActor{{Kind: "User", Name: "delegate"}}, Scope: privacy.PolicyScope{ClusterIDs: []string{permissionCluster}}}}}
			p, b, err := RetentionAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			p.UID = types.UID("policy")
			p.Generation = 1
			p.ResourceVersion = "one"
			p.Status.ObservedGeneration = 1
			p.Status.TypeChecking = &admission.TypeChecking{}
			b.UID = types.UID("binding")
			b.ResourceVersion = "one"
			pin := GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "one"}
			switch mode {
			case "warn-only":
				b.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
			case "wrong-uid":
				p.UID = "replacement"
			case "not-typechecked":
				p.Status.TypeChecking = nil
			}
			var f permissionFixture
			probes := 0
			f = newRetentionGuardFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				switch {
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
					permissionReply(w, p)
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
					permissionReply(w, b)
				case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
					who := "outsider"
					switch mode {
					case "probe-admin":
						who = "admin"
					case "probe-delegate":
						who = "delegate"
					case "probe-status":
						who = "status"
					}
					permissionReply(w, authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authentication.SelfSubjectReviewStatus{UserInfo: authentication.UserInfo{Username: who, Groups: []string{"authenticated"}}}})
				case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
					permissionReply(w, authorization.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: authorization.SubjectAccessReviewStatus{Allowed: mode != "rbac-denied"}})
				case strings.HasSuffix(r.URL.Path, "/evidenceretentionpolicies"):
					if r.Method != "POST" || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" {
						t.Error("probe could persist policy")
					}
					probes++
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid probe")
					}
					if mode == "admission-allows" {
						permissionReply(w, body)
						return true
					}
					cause := "ValidatingAdmissionPolicy 'retention-guard' with binding 'retention-guard' denied request: Asservat retention administrator or matching retention delegation is required."
					if mode == "wrong-cause" {
						cause = "unrelated refusal"
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(422)
					permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Group: "asservat.io", Kind: "evidenceretentionpolicies", Causes: []meta.StatusCause{{Message: cause}}}})
					if mode == "changed-during-probe" {
						p.ResourceVersion = "two"
					}
					if mode == "expired" {
						f.clock.Add(int64(6 * time.Second))
					}
				case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") && mode == "namespace-replaced":
					permissionReply(w, permissionNamespace(permissionControl.Name, "replacement"))
				default:
					return false
				}
				return true
			})
			probe := *f.client // synthetic endpoint supplies a fixed probe identity
			guard, err := NewRetentionGuard(f.client, &probe, plan, pin)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := guard.RetentionProtection(context.Background())
			if mode == "valid" {
				if err != nil || trust.FreshUntil.Sub(trust.ObservedAt) != 5*time.Second || trust.ControlNamespaceUID != permissionControl.UID || trust.SourceClusterID != permissionCluster || probes != 1 {
					t.Fatal("current guard", trust, err)
				}
			} else if err == nil {
				t.Fatal("invalid enforcement accepted", mode)
			}
			if strings.HasPrefix(mode, "probe-") || mode == "rbac-denied" {
				if probes != 0 {
					t.Fatal("ineligible negative control reached dry run")
				}
			}
		})
	}
}

func newRetentionGuardFixture(t *testing.T, hook func(http.ResponseWriter, *http.Request) bool) permissionFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(time.Now().UTC().UnixNano())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-only" {
			t.Error("wrong proof credential")
		}
		if r.Method != "GET" && r.Method != "POST" {
			t.Error("unexpected proof method")
		}
		if hook(w, r) {
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		t.Error("unexpected proof path")
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	client, err := NewPermissionClient(config, permissionCluster, permissionControl, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return permissionFixture{client: client, config: config, clock: clock}
}
