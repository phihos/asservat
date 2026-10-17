package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func TestInitialCredentialStateNativeGuardAndUncertainCreate(t *testing.T) {
	for _, mode := range []string{"valid", "lost-reply", "different-content", "wrong-admin", "launched-pod", "missing-guard", "guard-lost-after-write", "expired-after-write", "forbidden-post", "history-terminal-pod", "history-wrong-witness", "history-expired-final", "history-missing-guard", "history-wrong-admin", "resolve-existing", "resolve-missing", "resolve-different"} {
		t.Run(mode, func(t *testing.T) {
			w, err := BuildInitialInstallerWorkload(initialWorkloadPlan())
			if err != nil {
				t.Fatal(err)
			}
			pod := w.Pod
			pod.TypeMeta = meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}
			pod.UID = types.UID(ownerID(2))
			pod.ResourceVersion = "1"
			p := cfg.InitialWorkloadAdministration{Name: "workload-guard", Configuration: "inputs", Witness: "witness", FleetSource: "fleet", ControlNamespace: cfg.NamespaceRef{Name: "install", UID: ownerID(1)}, PodName: pod.Name, PodUID: string(pod.UID), WriterAccount: "writer", WriterAccountUID: ownerID(3), ProbeAccount: "probe", ProbeAccountUID: ownerID(4), PodSpecDigest: InstallationPodSpecDigest(pod.Spec), Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
			policy, binding, err := InitialWorkloadAdmission(p)
			if err != nil {
				t.Fatal(err)
			}
			policy.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}
			policy.UID = types.UID(ownerID(5))
			policy.Generation = 1
			policy.ResourceVersion = "1"
			policy.Status.ObservedGeneration = 1
			policy.Status.TypeChecking = &admission.TypeChecking{}
			binding.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}
			binding.UID = types.UID(ownerID(6))
			binding.ResourceVersion = "1"
			pin := GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: 1, BindingUID: string(binding.UID), BindingResourceVersion: "1"}
			ref := func(name string, n int) contracts.WorkerObjectReference {
				return contracts.WorkerObjectReference{Name: name, UID: ownerID(n)}
			}
			input := contracts.InitialInstaller{Format: contracts.InitialInstallerFormat, InstallationID: ownerID(8), IssuerEpoch: ownerID(9), ClusterID: ownerID(10), Namespace: ref("install", 1), Pod: ref(pod.Name, 2), WriterAccount: ref("writer", 3), ProbeAccount: ref("probe", 4), Configuration: "inputs", Witness: ref("witness", 12), PodSpecDigest: hex.EncodeToString(p.PodSpecDigest[:])}
			inputBytes, _ := json.Marshal(input)
			sum := artifact.Digest(sha256.Sum256(inputBytes))
			cm := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: "inputs", Namespace: "install", UID: types.UID(ownerID(7)), ResourceVersion: "1"}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(inputBytes)}}
			state, _ := json.Marshal(contracts.InitialSQLCredentialState{Format: contracts.InitialSQLCredentialsFormat, InstallationID: input.InstallationID, PlanDigest: hex.EncodeToString(sum[:])})
			defer clear(state)
			if mode == "launched-pod" {
				pod.Spec.NodeName = "node"
				pod.Spec.SchedulingGates = nil
			}
			var posts, reads atomic.Int32
			var after atomic.Bool
			now := time.Now()
			clock := func() time.Time {
				if (mode == "expired-after-write" || mode == "history-expired-final") && after.Load() {
					return now.Add(6 * time.Second)
				}
				return now
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				status := func(code int, reason meta.StatusReason, kind, cause string) {
					out.Header().Set("Content-Type", "application/json")
					out.WriteHeader(code)
					permissionReply(out, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code), Details: &meta.StatusDetails{Kind: kind, Causes: []meta.StatusCause{{Message: cause}}}})
				}
				switch r.URL.Path {
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					who := auth.SelfSubjectReview{}
					who.Status.UserInfo = auth.UserInfo{Username: "operator", Groups: []string{"system:authenticated"}}
					if r.Header.Get("Authorization") == "Bearer probe" {
						who.Status.UserInfo.Username = "system:serviceaccount:install:probe"
						who.Status.UserInfo.UID = p.ProbeAccountUID
					} else if mode == "wrong-admin" || mode == "history-wrong-admin" {
						who.Status.UserInfo.Username = "ordinary"
					}
					permissionReply(out, who)
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					a := authz.SelfSubjectAccessReview{}
					a.Status.Allowed = true
					permissionReply(out, a)
				case "/api/v1/namespaces/install":
					permissionReply(out, core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "install", UID: types.UID(p.ControlNamespace.UID), ResourceVersion: "1"}})
				case "/api/v1/namespaces/install/serviceaccounts/probe", "/api/v1/namespaces/install/serviceaccounts/writer":
					name, uid := p.ProbeAccount, p.ProbeAccountUID
					if strings.HasSuffix(r.URL.Path, "/writer") {
						name, uid = p.WriterAccount, p.WriterAccountUID
					}
					permissionReply(out, core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "install", UID: types.UID(uid), ResourceVersion: "1"}})
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/workload-guard":
					permissionReply(out, policy)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/workload-guard":
					if (mode == "missing-guard" || mode == "history-missing-guard") || mode == "guard-lost-after-write" && after.Load() {
						status(404, meta.StatusReasonNotFound, "validatingadmissionpolicybindings", "")
						return
					}
					permissionReply(out, binding)
				case "/api/v1/namespaces/install/configmaps/inputs":
					if r.Method == "PUT" {
						if r.URL.Query().Get("dryRun") != "All" {
							t.Error("persistent guard probe")
						}
						status(403, meta.StatusReasonForbidden, "configmaps", "ValidatingAdmissionPolicy 'workload-guard' with binding 'workload-guard' denied request: "+initialWorkloadDenial)
						return
					}
					permissionReply(out, cm)
					if mode == "history-expired-final" {
						after.Store(true)
					}
				case "/api/v1/namespaces/install/pods/installer":
					if strings.HasPrefix(mode, "history-") {
						t.Error("historical read depended on old Pod")
					}
					permissionReply(out, pod)
				case "/api/v1/namespaces/install/secrets", "/api/v1/namespaces/install/secrets/sql-state":
					if r.Method == "POST" {
						posts.Add(1)
						body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
						var secret core.Secret
						if json.Unmarshal(body, &secret) != nil || !bytes.Equal(secret.Data["state.json"], state) {
							t.Error("wrong secret request")
						}
						clear(body)
						if mode == "forbidden-post" {
							status(403, meta.StatusReasonForbidden, "secrets", "")
							return
						}
						after.Store(true)
						if mode == "lost-reply" {
							status(500, meta.StatusReasonInternalError, "secrets", "")
							return
						}
					} else {
						reads.Add(1)
						if mode == "resolve-missing" {
							status(404, meta.StatusReasonNotFound, "secrets", "")
							return
						}
					}
					value := append([]byte(nil), state...)
					if mode == "different-content" || mode == "resolve-different" {
						value = append([]byte(" "), value...)
					}
					permissionReply(out, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "sql-state", Namespace: "install", UID: types.UID(ownerID(11)), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"state.json": value}})
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
					http.NotFound(out, r)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client := func(token string) *PermissionClient {
				c, e := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, input.ClusterID, p.ControlNamespace, clock)
				if e != nil {
					t.Fatal(e)
				}
				return c
			}
			s, err := NewInitialCredentialStateStore(client("operator"), client("probe"), p, pin, string(cm.UID), input.InstallationID, "sql-state", sum)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "history-") {
				scope := value.InstallationWitnessScope{InstallationID: input.InstallationID, IssuerEpoch: input.IssuerEpoch, ClusterID: input.ClusterID, Namespace: input.Namespace.Name, NamespaceUID: input.Namespace.UID, Name: input.Witness.Name, UID: input.Witness.UID, WriterAccount: input.WriterAccount.Name, WriterAccountUID: input.WriterAccount.UID}
				if mode == "history-wrong-witness" {
					scope.UID = ownerID(20)
				}
				reader, e := NewInitialInstallationReadProtection(client("operator"), client("probe"), p, pin, string(cm.UID), scope, sum)
				if e != nil {
					t.Fatal(e)
				}
				pod.Status.Phase = core.PodFailed
				until, e := reader.CheckInitialInstallationRead(context.Background(), scope, sum)
				if (e == nil) != (mode == "history-terminal-pod") {
					t.Fatal("historical protection outcome", mode, e)
				}
				if e == nil && !until.Equal(now.Add(5*time.Second)) {
					t.Fatal("original observation extended")
				}
				if posts.Load() != 0 || reads.Load() != 0 {
					t.Fatal("historical protection read or created credential Secret")
				}
				return
			}
			if strings.HasPrefix(mode, "resolve-") {
				got, e := s.ResolveCreate(context.Background(), state)
				if (e == nil) != (mode == "resolve-existing") {
					t.Fatal("unexpected read-only resolution", mode, e)
				}
				if e == nil && got != ref("sql-state", 11) {
					t.Fatal("wrong original Secret reference")
				}
				if posts.Load() != 0 || reads.Load() != 1 {
					t.Fatal("resolution repeated issuance or skipped original lookup", posts.Load(), reads.Load())
				}
				return
			}
			got, err := s.Create(context.Background(), state)
			good := mode == "valid" || mode == "lost-reply"
			if (err == nil) != good {
				t.Fatal("unexpected state outcome", mode, err)
			}
			if good && got != ref("sql-state", 11) {
				t.Fatal("wrong retained secret identity")
			}
			if posts.Load() > 1 || mode == "lost-reply" && (posts.Load() != 1 || reads.Load() != 1) || mode == "forbidden-post" && reads.Load() != 0 {
				t.Fatal("POST replay or unexpected lookup", posts.Load(), reads.Load())
			}
			if (mode == "wrong-admin" || mode == "launched-pod" || mode == "missing-guard") && posts.Load() != 0 {
				t.Fatal("secret written before protection")
			}
		})
	}
}
