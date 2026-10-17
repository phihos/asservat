package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestInitialNamespaceCreationKeepsUncertaintyAndExactIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "existing-namespace", "wrong-admin", "admin-lost", "policy-collision", "binding-lost-reply", "namespace-lost-reply", "namespace-missing-label", "namespace-missing-stamp", "namespace-replaced", "policy-replaced", "binding-replaced", "policy-changed", "guard-lost"} {
		t.Run(mode, func(t *testing.T) {
			plan := cfg.InitialNamespaceAdministration{Name: "stage", Namespace: "install", ProbeSource: "preparation", Inputs: "inputs", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
			var policy admission.ValidatingAdmissionPolicy
			var binding admission.ValidatingAdmissionPolicyBinding
			var namespace core.Namespace
			var writes []string
			var resumed bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				status := func(code int, reason meta.StatusReason) {
					out.Header().Set("Content-Type", "application/json")
					out.WriteHeader(code)
					permissionReply(out, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
				}
				if r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
					who := auth.SelfSubjectReview{}
					who.Status.UserInfo = auth.UserInfo{Username: "operator", Groups: []string{"system:authenticated"}}
					if mode == "wrong-admin" || mode == "admin-lost" && len(writes) > 0 {
						who.Status.UserInfo.Username = "ordinary"
					}
					permissionReply(out, who)
					return
				}
				if r.Method == http.MethodPost {
					if resumed || r.URL.Query().Get("fieldValidation") != "Strict" {
						t.Error("unexpected create or missing strict validation")
					}
					writes = append(writes, r.URL.Path)
					switch r.URL.Path {
					case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies":
						if mode == "policy-collision" {
							status(409, meta.StatusReasonAlreadyExists)
							return
						}
						if json.NewDecoder(r.Body).Decode(&policy) != nil {
							t.Error("invalid policy")
						}
						policy.UID, policy.ResourceVersion, policy.Generation = types.UID(ownerID(3)), "1", 1
						policy.Status.ObservedGeneration = 1
						policy.Status.TypeChecking = &admission.TypeChecking{}
						permissionReply(out, policy)
					case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings":
						if json.NewDecoder(r.Body).Decode(&binding) != nil {
							t.Error("invalid binding")
						}
						binding.UID, binding.ResourceVersion = types.UID(ownerID(4)), "2"
						if mode == "binding-lost-reply" {
							status(500, meta.StatusReasonInternalError)
							return
						}
						permissionReply(out, binding)
					case "/api/v1/namespaces":
						if json.NewDecoder(r.Body).Decode(&namespace) != nil {
							t.Error("invalid namespace")
						}
						namespace.UID, namespace.ResourceVersion = types.UID(ownerID(5)), "3"
						if mode == "namespace-lost-reply" {
							status(500, meta.StatusReasonInternalError)
							return
						}
						if mode == "namespace-missing-label" {
							namespace.Labels = nil
						}
						if mode == "namespace-missing-stamp" {
							namespace.Annotations = nil
						}
						permissionReply(out, namespace)
					default:
						t.Error("unexpected POST", r.URL.Path)
						status(400, meta.StatusReasonBadRequest)
					}
					return
				}
				if r.Method != http.MethodGet {
					t.Error("unexpected mutation", r.Method)
				}
				switch {
				case r.URL.Path == "/api/v1/namespaces/install":
					if namespace.UID == "" && mode != "existing-namespace" {
						status(404, meta.StatusReasonNotFound)
						return
					}
					if resumed && mode == "namespace-replaced" {
						namespace.UID = types.UID(ownerID(6))
					}
					permissionReply(out, namespace)
				case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies/stage"):
					if mode == "policy-replaced" {
						policy.UID = types.UID(ownerID(6))
					}
					if mode == "policy-changed" {
						policy.Spec.Validations[0].Expression = "true"
					}
					permissionReply(out, policy)
				case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/stage"):
					if mode == "guard-lost" {
						status(404, meta.StatusReasonNotFound)
						return
					}
					if mode == "binding-replaced" {
						binding.UID = types.UID(ownerID(6))
					}
					permissionReply(out, binding)
				default:
					t.Error("unexpected GET", r.URL.Path)
					status(404, meta.StatusReasonNotFound)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			creator, err := NewInitialNamespaceCreator(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, plan, ownerID(1), ownerID(2))
			if err != nil {
				t.Fatal(err)
			}
			refs, err := creator.CreateNew(context.Background())
			goodCreate := mode == "valid" || strings.HasSuffix(mode, "replaced") || mode == "policy-changed" || mode == "guard-lost"
			if (err == nil) != goodCreate {
				t.Fatal("unexpected creation result", refs, err)
			}
			wantWrites := 3
			switch mode {
			case "existing-namespace", "wrong-admin":
				wantWrites = 0
			case "admin-lost", "policy-collision":
				wantWrites = 1
			case "binding-lost-reply":
				wantWrites = 2
			}
			if len(writes) != wantWrites {
				t.Fatal("replayed create or proceeded after uncertain result", writes)
			}
			if mode == "binding-lost-reply" && (refs.Guard.PolicyUID != ownerID(3) || refs.Guard.BindingUID != "" || refs.Namespace.UID != "") {
				t.Fatal("lost acknowledged policy or invented binding receipt", refs)
			}
			if mode == "namespace-lost-reply" && (refs.Guard.BindingUID != ownerID(4) || refs.Namespace.UID != "") {
				t.Fatal("lost acknowledged binding or invented namespace receipt", refs)
			}
			if !goodCreate {
				return
			}
			resumed = true
			if err := creator.Resume(context.Background(), refs); (err == nil) != (mode == "valid") {
				t.Fatal("unexpected exact-identity resumption", err)
			}
			if len(writes) != wantWrites {
				t.Fatal("resumption mutated resources")
			}
		})
	}
}
