package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// This exercises the concrete adapter against a synthetic HTTPS API. It does
// not qualify native TokenReview, admission or installation provenance.
func TestClusterObservationCallerExactNativeReadBoundary(t *testing.T) {
	for _, mode := range []string{"valid", "parent-cap", "token-cap", "wrong-audience", "unbound", "wrong-account", "extra-admin-group", "duplicate-group", "revoked-review", "replaced-account", "replaced-pod", "replaced-controller", "two-controllers", "changed-template", "changed-pod-command", "changed-after-read", "scaled-down", "deleted-pod", "lost-guard", "other-policy", "late-final-guard", "original-expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now().UTC()
			var clock atomic.Int64
			clock.Store(start.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			v := ownerFixtureObjects()
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, ControlNamespace: cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "Group", Name: "system:masters"}}}
			policy, binding, e := OwnerWorkloadAdmission(plan)
			if e != nil {
				t.Fatal(e)
			}
			guardPin := GuardPin{PolicyUID: ownerID(31), PolicyGeneration: 1, BindingUID: ownerID(32), BindingResourceVersion: "20"}
			policy.UID, policy.Generation, policy.ResourceVersion = types.UID(guardPin.PolicyUID), 1, "10"
			policy.Status.ObservedGeneration = 1
			policy.Status.TypeChecking = &admission.TypeChecking{}
			binding.UID, binding.ResourceVersion = types.UID(guardPin.BindingUID), guardPin.BindingResourceVersion
			d, rs, pod, image := connectorAPITemplateFixture()
			md := func(name string, id int) meta.ObjectMeta {
				return meta.ObjectMeta{Name: name, Namespace: v.pool.Namespace, UID: types.UID(ownerID(id)), ResourceVersion: "10"}
			}
			d.TypeMeta = meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}
			d.ObjectMeta = md("hwork", 50)
			d.Spec.Replicas = ptr.To(int32(1))
			d.Spec.Selector = &meta.LabelSelector{MatchLabels: map[string]string{"app": "connector"}}
			rs.TypeMeta = meta.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}
			rs.ObjectMeta = md("hwork-rs", 51)
			rs.Spec.Replicas = ptr.To(int32(1))
			rs.OwnerReferences = []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: ptr.To(true)}}
			pod.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
			pod.Name, pod.Namespace, pod.UID, pod.ResourceVersion = "hwork-rs-pod", v.pool.Namespace, types.UID(ownerID(52)), "10"
			pod.Status.Phase = core.PodRunning
			pod.OwnerReferences = []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: ptr.To(true)}}
			sa := core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: md("connector", 53)}
			template, e := ConnectorAPITemplateDigest(d.Spec.Template)
			if e != nil {
				t.Fatal(e)
			}
			pin := fleet.ClusterObservationCallerPin{RootID: ownerID(60), InstallationID: v.pool.InstallationID, ClusterID: v.pool.ClusterID, Namespace: plan.ControlNamespace, Account: sa.Name, AccountUID: string(sa.UID), Deployment: d.Name, DeploymentUID: string(d.UID), TemplateDigest: template, ImageDigest: image}
			var reviews, probes, podReads atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-observer" && r.Header.Get("Authorization") != "Bearer synthetic-probe" {
					t.Error("API credential mixed with caller token")
				}
				switch r.URL.Path {
				case "/api/v1/namespaces/owners":
					permissionReply(w, v.ns)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/owner-workload":
					if mode == "lost-guard" && reviews.Load() == 2 {
						http.NotFound(w, r)
						return
					}
					permissionReply(w, policy)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/owner-workload":
					permissionReply(w, binding)
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					permissionReply(w, auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: "probe", Groups: []string{"system:authenticated"}}}})
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					permissionReply(w, access.SelfSubjectAccessReview{Status: access.SubjectAccessReviewStatus{Allowed: true}})
				case "/apis/apps/v1/namespaces/owners/deployments/hub":
					if r.Method == http.MethodGet {
						permissionReply(w, v.deploy)
						return
					}
					if r.Method != http.MethodPut || r.URL.Query().Get("dryRun") != "All" {
						t.Error("non-dry-run guard request")
					}
					n := probes.Add(1)
					if mode == "late-final-guard" && n == 2 {
						clock.Store(start.Add(3 * time.Second).UnixNano())
					}
					message := "ValidatingAdmissionPolicy 'owner-workload' with binding 'owner-workload' denied request: " + ownerWorkloadDenial
					if mode == "other-policy" {
						message = strings.ReplaceAll(message, "owner-workload", "other-policy")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: message}}}})
				case "/apis/authentication.k8s.io/v1/tokenreviews":
					n := reviews.Add(1)
					var q auth.TokenReview
					if json.NewDecoder(r.Body).Decode(&q) != nil || len(q.Spec.Audiences) != 1 || q.Spec.Audiences[0] != fleet.ClusterObservationAudience(pin.InstallationID) {
						t.Error("wrong purpose-bound TokenReview")
					}
					u := auth.UserInfo{Username: "system:serviceaccount:owners:connector", UID: pin.AccountUID, Groups: []string{"system:serviceaccounts", "system:authenticated", "system:serviceaccounts:owners"}, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}
					s := auth.TokenReviewStatus{Authenticated: true, Audiences: q.Spec.Audiences, User: u}
					switch mode {
					case "wrong-audience":
						s.Audiences = []string{"other"}
					case "unbound":
						delete(s.User.Extra, "authentication.kubernetes.io/pod-uid")
					case "wrong-account":
						s.User.UID = ownerID(99)
					case "extra-admin-group":
						s.User.Groups = append(s.User.Groups, "system:masters")
					case "duplicate-group":
						s.User.Groups = append(s.User.Groups, "system:authenticated")
					case "revoked-review":
						if n == 2 {
							s.Authenticated = false
						}
					}
					permissionReply(w, auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: s})
				case "/api/v1/namespaces/owners/serviceaccounts/connector":
					o := sa.DeepCopy()
					if mode == "replaced-account" {
						o.UID = types.UID(ownerID(99))
					}
					permissionReply(w, o)
				case "/apis/apps/v1/namespaces/owners/deployments/hwork":
					o := d.DeepCopy()
					if mode == "scaled-down" {
						o.Spec.Replicas = ptr.To(int32(0))
					}
					if mode == "changed-template" {
						o.Spec.Template.Spec.Containers[0].Args = []string{"changed"}
					}
					permissionReply(w, o)
				case "/apis/apps/v1/namespaces/owners/replicasets/hwork-rs":
					o := rs.DeepCopy()
					if mode == "replaced-controller" {
						o.OwnerReferences[0].UID = types.UID(ownerID(99))
					}
					permissionReply(w, o)
				case "/api/v1/namespaces/owners/pods/hwork-rs-pod":
					n := podReads.Add(1)
					o := pod.DeepCopy()
					switch mode {
					case "replaced-pod":
						o.UID = types.UID(ownerID(99))
					case "two-controllers":
						o.OwnerReferences = append(o.OwnerReferences, o.OwnerReferences[0])
					case "changed-pod-command":
						o.Spec.Containers[0].Command = []string{"other"}
					case "changed-after-read":
						if n > 1 {
							o.Spec.Containers[0].Args = []string{"other"}
						}
					case "deleted-pod":
						o.DeletionTimestamp = &meta.Time{Time: start}
					}
					permissionReply(w, o)
				default:
					t.Errorf("unexpected API path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client := func(token string) *PermissionClient {
				c, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: root}, BearerToken: token}, pin.ClusterID, pin.Namespace, now)
				if e != nil {
					t.Fatal(e)
				}
				return c
			}
			observer, probe := client("synthetic-observer"), client("synthetic-probe")
			guard, e := NewOwnerWorkloadProtection(observer, probe, plan, guardPin)
			if e != nil {
				t.Fatal(e)
			}
			pin.ProtectionDigest = guard.digest
			a, e := NewClusterObservationCallerAdmission(observer, guard, pin)
			if e != nil {
				t.Fatal(e)
			}
			expires := start.Add(time.Minute).Truncate(time.Second)
			if mode == "token-cap" {
				expires = start.Add(3 * time.Second).Truncate(time.Second)
			}
			claims, _ := json.Marshal(map[string]int64{"iat": start.Add(-time.Second).Unix(), "exp": expires.Unix()})
			token := []byte("e30." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic")
			request := fleet.ClusterObservationRequest{ID: ownerID(70), Challenge: ownerID(71), RootID: pin.RootID, ClusterID: ownerID(72), Purpose: fleet.ObserveCapacityNamespaceGuard, RequestedAt: start, NotAfter: start.Add(5 * time.Second)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "parent-cap" || mode == "late-final-guard" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, start.Add(2*time.Second))
				defer stop()
			}
			if mode == "original-expired" {
				clock.Store(request.NotAfter.UnixNano())
			}
			if mode == "cancelled" {
				cancel()
			}
			got, e := a.ObserveClusterObservationCaller(ctx, token, string(pod.UID), request)
			if mode == "valid" || mode == "parent-cap" || mode == "token-cap" {
				if e != nil || !got.Matches(request, now()) || got.Pin != pin || got.PodUID != string(pod.UID) || reviews.Load() != 2 || podReads.Load() != 2 || probes.Load() != 2 {
					t.Fatalf("exact current caller denied: %v", e)
				}
				if d, ok := ctx.Deadline(); ok && got.FreshUntil.After(d) {
					t.Fatal("caller parent deadline renewed")
				}
				if got.FreshUntil.After(expires) {
					t.Fatal("token deadline renewed")
				}
			} else if e == nil {
				t.Fatal("invalid/changed local caller admitted")
			}
		})
	}
}
