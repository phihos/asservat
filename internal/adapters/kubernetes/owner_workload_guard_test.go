package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestOwnerWorkloadProtectionRequiresActualCurrentDenial(t *testing.T) {
	for _, mode := range []string{"valid", "conflict-once", "conflict-always", "conflict-foreign", "conflict-then-replaced", "conflict-then-late", "ordinary-rbac-denial", "admin-probe", "controller-probe", "changed-binding", "changed-policy", "type-warning", "missing-policy", "foreign-deployment", "namespace-replaced", "namespace-replaced-after", "late", "wrong-cause", "wrong-kind", "accepted-dry-run", "changed-during-proof"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			var clock atomic.Int64
			clock.Store(start.UnixNano())
			plan := cfg.OwnerWorkloadAdministration{SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: "reconcile", ServiceAccount: "reconciler"}}, Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "source-probe"}}}
			policy, binding, err := OwnerWorkloadAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			pin := GuardPin{PolicyUID: ownerID(1), PolicyGeneration: 1, BindingUID: ownerID(2), BindingResourceVersion: "20"}
			policy.UID, policy.Generation, policy.ResourceVersion = types.UID(pin.PolicyUID), 1, "10"
			policy.Status.ObservedGeneration = 1
			policy.Status.TypeChecking = &admission.TypeChecking{}
			binding.UID, binding.ResourceVersion = types.UID(pin.BindingUID), "20"
			deployment := apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: plan.Deployment, Namespace: plan.ControlNamespace.Name, UID: types.UID(plan.DeploymentUID), ResourceVersion: "30"}}
			var policyReads, namespaceReads, deploymentReads, writes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/namespaces/owners":
					uid := plan.ControlNamespace.UID
					n := namespaceReads.Add(1)
					if mode == "namespace-replaced" || mode == "namespace-replaced-after" && n > 1 {
						uid = ownerID(99)
					}
					permissionReply(w, permissionNamespace("owners", uid))
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/owner-workload":
					n := policyReads.Add(1)
					p := policy.DeepCopy()
					if mode == "missing-policy" {
						http.NotFound(w, r)
						return
					}
					if mode == "changed-policy" {
						p.Spec.Validations[0].Expression = "true"
					}
					if mode == "type-warning" {
						p.Status.TypeChecking.ExpressionWarnings = []admission.ExpressionWarning{{FieldRef: "spec", Warning: "unsafe"}}
					}
					if mode == "changed-during-proof" && n > 1 {
						p.ResourceVersion = "changed"
					}
					permissionReply(w, p)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/owner-workload":
					b := binding.DeepCopy()
					if mode == "changed-binding" {
						b.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
					}
					permissionReply(w, b)
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					who := auth.SelfSubjectReview{}
					who.Status.UserInfo.Username = "probe"
					who.Status.UserInfo.Groups = []string{"system:authenticated"}
					if mode == "admin-probe" {
						who.Status.UserInfo.Username = "installer"
					}
					if mode == "controller-probe" {
						who.Status.UserInfo.Username = ownerControllerUser("replicaset-controller")
					}
					permissionReply(w, who)
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var req authorization.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&req) != nil || req.Spec.ResourceAttributes.Name != "hub" || req.Spec.ResourceAttributes.Verb != "update" || req.Spec.ResourceAttributes.Group != "apps" {
						t.Error("wrong probe authorization")
					}
					req.Status.Allowed = mode != "ordinary-rbac-denial"
					permissionReply(w, req)
				case "/apis/apps/v1/namespaces/owners/deployments/hub":
					if r.Method == http.MethodGet {
						deploymentReads.Add(1)
						p := deployment.DeepCopy()
						p.ResourceVersion = strconv.Itoa(30 + int(writes.Load()))
						if mode == "foreign-deployment" || mode == "conflict-then-replaced" && writes.Load() > 0 {
							p.UID = types.UID(ownerID(99))
						}
						permissionReply(w, p)
						return
					}
					attempt := writes.Add(1)
					if r.Method != http.MethodPut || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" {
						t.Error("unsafe probe")
					}
					var actual apps.Deployment
					expected := deployment.DeepCopy()
					expected.ResourceVersion = strconv.Itoa(29 + int(attempt))
					if json.NewDecoder(r.Body).Decode(&actual) != nil || !equalJSON(actual, expected) {
						t.Error("probe changed workload")
					}
					if mode == "conflict-always" || attempt == 1 && (mode == "conflict-once" || mode == "conflict-foreign" || mode == "conflict-then-replaced" || mode == "conflict-then-late") {
						name := plan.Deployment
						if mode == "conflict-foreign" {
							name = "other"
						}
						if mode == "conflict-then-late" {
							clock.Store(start.Add(5 * time.Second).UnixNano())
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusConflict)
						_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonConflict, Code: 409, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Name: name}})
						return
					}
					if mode == "accepted-dry-run" {
						permissionReply(w, deployment)
						return
					}
					if mode == "late" {
						clock.Store(start.Add(5 * time.Second).UnixNano())
					}
					cause := "ValidatingAdmissionPolicy 'owner-workload' with binding 'owner-workload' denied request: " + ownerWorkloadDenial
					if mode == "wrong-cause" {
						cause = "some other policy denied this"
					}
					kind := "deployments"
					if mode == "wrong-kind" {
						kind = "pods"
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: kind, Causes: []meta.StatusCause{{Message: cause}}}})
				default:
					t.Error("unexpected path", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			reader, e := NewPermissionClient(config, permissionCluster, plan.ControlNamespace, now)
			if e != nil {
				t.Fatal(e)
			}
			probe, e := NewPermissionClient(config, permissionCluster, plan.ControlNamespace, now)
			if e != nil {
				t.Fatal(e)
			}
			guard, e := NewOwnerWorkloadProtection(reader, probe, plan, pin)
			if e != nil {
				t.Fatal(e)
			}
			// Caller-owned plans cannot change a live guard after qualification.
			plan.Administrators[0].Name = "mutated-caller"
			plan.ConfigurationProbes[0].ConfigMap = "mutated-caller"
			plan.SchedulingLeases[0].Lease = "mutated-caller"
			digest, until, e := guard.Current(context.Background())
			if mode == "valid" {
				if e != nil || digest != guard.digest || !until.Equal(start.Add(5*time.Second)) || writes.Load() != 1 {
					t.Fatal("valid guard", e)
				}
				pool := value.OwnerPool{InstallationID: ownerID(6), ClusterID: permissionCluster, IssuerEpoch: ownerID(7), Namespace: plan.ControlNamespace.Name, NamespaceUID: plan.ControlNamespace.UID, Deployment: plan.Deployment, DeploymentUID: plan.DeploymentUID, Service: "hub", ServiceUID: ownerID(8), ServiceAccount: "hub", AccountUID: ownerID(9), Port: 8443}
				if observed, e := guard.ReadOwnerProtection(context.Background(), pool); e != nil || !observed.Valid(now()) || observed.Pool != pool || observed.Digest != digest || !observed.FreshUntil.Equal(until) {
					t.Fatal("pool-bound protection", e)
				}
				reads := policyReads.Load()
				for _, field := range []string{"cluster", "namespace", "namespace-uid", "deployment", "deployment-uid"} {
					changed := pool
					switch field {
					case "cluster":
						changed.ClusterID = ownerID(10)
					case "namespace":
						changed.Namespace = "other"
					case "namespace-uid":
						changed.NamespaceUID = ownerID(10)
					case "deployment":
						changed.Deployment = "other"
					case "deployment-uid":
						changed.DeploymentUID = ownerID(10)
					}
					if _, e = guard.ReadOwnerProtection(context.Background(), changed); e == nil || policyReads.Load() != reads {
						t.Fatal("foreign workload reached proof", field, e)
					}
				}
			} else if mode == "conflict-once" {
				if e != nil || digest != guard.digest || !until.Equal(start.Add(5*time.Second)) || writes.Load() != 2 || deploymentReads.Load() != 2 {
					t.Fatalf("bounded conflict retry: %v, writes=%d, until=%v", e, writes.Load(), until)
				}
			} else if e == nil {
				t.Fatal("unsafe proof accepted")
			}
			if mode == "conflict-always" && writes.Load() != 3 {
				t.Fatalf("conflict retries not bounded: %d", writes.Load())
			}
			if (mode == "conflict-foreign" || mode == "conflict-then-replaced" || mode == "conflict-then-late" || mode == "wrong-cause" || mode == "accepted-dry-run") && writes.Load() != 1 {
				t.Fatalf("unsafe conflict retried: %d", writes.Load())
			}
			if (mode == "ordinary-rbac-denial" || mode == "admin-probe" || mode == "controller-probe") && writes.Load() != 0 {
				t.Fatal("invalid probe attempted mutation")
			}
		})
	}
}

func TestOwnerWorkloadProbePlanRejectsAmbiguousScope(t *testing.T) {
	for _, mode := range []string{"empty-source", "wildcard-source", "foreign-account", "duplicate", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "source-probe"}}}
			switch mode {
			case "empty-source":
				plan.ConfigurationProbes[0].ConfigMap = ""
			case "wildcard-source":
				plan.ConfigurationProbes[0].ConfigMap = "*"
			case "foreign-account":
				plan.ConfigurationProbes[0].ServiceAccount = "other/source-probe"
			case "duplicate":
				plan.ConfigurationProbes = append(plan.ConfigurationProbes, plan.ConfigurationProbes[0])
			case "too-many":
				plan.ConfigurationProbes = make([]cfg.OwnerConfigurationProbe, 9)
			}
			if _, _, err := OwnerWorkloadAdmission(plan); err == nil {
				t.Fatal("unsafe source probe scope accepted")
			}
		})
	}
}

func TestOwnerSchedulingLeasePlanRejectsAmbiguousScope(t *testing.T) {
	for _, mode := range []string{"empty-lease", "wildcard-lease", "foreign-account", "duplicate", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "hub", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, SchedulingLeases: []cfg.OwnerSchedulingLease{{Lease: "reconcile", ServiceAccount: "reconciler"}}}
			switch mode {
			case "empty-lease":
				plan.SchedulingLeases[0].Lease = ""
			case "wildcard-lease":
				plan.SchedulingLeases[0].Lease = "*"
			case "foreign-account":
				plan.SchedulingLeases[0].ServiceAccount = "other/reconciler"
			case "duplicate":
				plan.SchedulingLeases = append(plan.SchedulingLeases, plan.SchedulingLeases[0])
			case "too-many":
				plan.SchedulingLeases = make([]cfg.OwnerSchedulingLease, 5)
			}
			if _, _, err := OwnerWorkloadAdmission(plan); err == nil {
				t.Fatal("unsafe scheduling scope accepted")
			}
		})
	}
}

// ADR-193: one exact credential Secret UPDATE exception for one account.
func TestOwnerCredentialSecretPlan(t *testing.T) {
	plan := cfg.OwnerWorkloadAdministration{Name: "connector-workload", Deployment: "connector", DeploymentUID: ownerID(5), ControlNamespace: cfg.NamespaceRef{Name: "region", UID: ownerID(4)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, CredentialSecrets: []cfg.OwnerCredentialSecret{{Secret: "cluster-credential", ServiceAccount: "connector"}}}
	policy, _, err := OwnerWorkloadAdmission(plan)
	if err != nil || !strings.Contains(policy.Spec.Validations[0].Expression, `request.resource.resource == 'secrets' && variables.subResource == '' && request.name == "cluster-credential" && request.userInfo.username == "system:serviceaccount:region:connector"`) {
		t.Fatal("credential Secret exception missing", err)
	}
	for _, mutate := range []func(*cfg.OwnerWorkloadAdministration){
		func(p *cfg.OwnerWorkloadAdministration) { p.CredentialSecrets[0].Secret = "*" },
		func(p *cfg.OwnerWorkloadAdministration) { p.CredentialSecrets[0].ServiceAccount = "other/connector" },
		func(p *cfg.OwnerWorkloadAdministration) {
			p.CredentialSecrets = append(p.CredentialSecrets, cfg.OwnerCredentialSecret{Secret: "second", ServiceAccount: "connector"})
		},
	} {
		bad := plan
		bad.CredentialSecrets = slices.Clone(plan.CredentialSecrets)
		mutate(&bad)
		if _, _, err := OwnerWorkloadAdmission(bad); err == nil {
			t.Fatal("unsafe credential Secret scope accepted")
		}
	}
}
