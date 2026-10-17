package kubernetes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type connectorTokenFunc func(context.Context) ([]byte, error)

func (f connectorTokenFunc) ReadConnectorPodToken(c context.Context) ([]byte, error) { return f(c) }

type connectorSourceFunc func(context.Context) (value.ConnectorIdentitySource, error)

func (f connectorSourceFunc) ReadConnectorIdentitySource(c context.Context) (value.ConnectorIdentitySource, error) {
	return f(c)
}
func TestConnectorProcessProofBeforeReadinessAndCurrentProtection(t *testing.T) {
	for _, mode := range []string{"observation/valid", "observation/configuration-changed", "observation/revoked-review", "observation/lost-protection", "observation/roles-changed", "observation/cancelled", "valid", "pending", "not-ready", "status-change", "short-token", "cached-configuration", "invalid-csr", "same-key", "foreign-binding", "suspended", "configuration-unavailable", "configuration-changed", "configuration-expired", "missing-protection", "lost-protection", "wrong-audience", "unbound", "wrong-account", "wrong-pod", "path-pod", "denied-review", "revoked-review", "duplicate-exp", "expired-token", "unbounded-token", "token-read-error", "token-error-redaction", "whitespace-token", "wrong-namespace", "wrong-live-account", "wrong-deployment", "wrong-replica", "wrong-owner", "two-owners", "wrong-selector", "unassigned", "host-network", "host-pid", "host-ipc", "injected-process", "deleted-pod", "failed-pod", "scaled-down", "template-account", "spec-changed", "late", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			observation := strings.HasPrefix(mode, "observation/")
			mode = strings.TrimPrefix(mode, "observation/")
			start := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			v := ownerFixtureObjects()
			v.deploy.Spec.Replicas = ptr.To(int32(1))
			v.deploy.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
			v.rs.Spec.Replicas = ptr.To(int32(1))
			v.rs.Spec.Selector = v.deploy.Spec.Selector.DeepCopy()
			v.rs.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
			plan := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, ControlNamespace: cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}}
			policy, binding, err := OwnerWorkloadAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			pin := GuardPin{PolicyUID: ownerID(11), PolicyGeneration: 1, BindingUID: ownerID(12), BindingResourceVersion: "20"}
			policy.UID, policy.Generation, policy.ResourceVersion = types.UID(pin.PolicyUID), 1, "10"
			policy.Status.ObservedGeneration = 1
			policy.Status.TypeChecking = &admission.TypeChecking{}
			binding.UID, binding.ResourceVersion = types.UID(pin.BindingUID), pin.BindingResourceVersion
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			_, serverKey, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			serverCSR, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, serverKey)
			if e != nil {
				t.Fatal(e)
			}
			peer := value.PeerBinding{InstallationID: v.binding.InstallationID, ClusterID: v.binding.ClusterID, IssuerEpoch: v.binding.IssuerEpoch, PeerID: ownerID(20), Role: value.ConnectorPeer}
			request := value.ConnectorProcessRequest{Process: value.ConnectorProcessIdentity{Binding: peer, PodUID: v.binding.PodUID, ProcessEpoch: v.binding.ProcessEpoch}, ClientCSRDER: csr, ServerCSRDER: serverCSR}
			if mode == "invalid-csr" {
				request.ClientCSRDER = bytes.Repeat([]byte{1}, 64)
			}
			if mode == "same-key" {
				request.ServerCSRDER = bytes.Clone(request.ClientCSRDER)
			}
			if mode == "foreign-binding" {
				request.Process.Binding.IssuerEpoch = ownerID(99)
			}
			var clock atomic.Int64
			clock.Store(start.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			iat, exp := start.Add(-time.Second).Unix(), start.Add(time.Minute).Unix()
			if mode == "short-token" {
				exp = start.Add(time.Second).Unix()
			}
			if mode == "expired-token" {
				exp = start.Unix()
			}
			if mode == "unbounded-token" {
				exp = start.Add(2 * time.Hour).Unix()
			}
			payload, _ := json.Marshal(map[string]int64{"iat": iat, "exp": exp})
			if mode == "duplicate-exp" {
				payload = []byte(`{"iat":1791633599,"exp":1791633660,"exp":1791633660}`)
			}
			token := []byte("e30." + base64.RawURLEncoding.EncodeToString(payload) + ".synthetic-signature")
			if mode == "whitespace-token" {
				token = append(token, ' ')
			}
			var reviews, calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				n := reviews.Load()
				switch r.URL.Path {
				case "/api/v1/namespaces/owners":
					p := v.ns.DeepCopy()
					if mode == "wrong-namespace" && n > 0 {
						p.UID = types.UID(ownerID(99))
					}
					permissionReply(w, p)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/owner-workload":
					if mode == "missing-protection" || mode == "lost-protection" && n == 2 {
						http.NotFound(w, r)
						return
					}
					permissionReply(w, policy)
				case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/owner-workload":
					permissionReply(w, binding)
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					x := auth.SelfSubjectReview{}
					x.Status.UserInfo.Username = "probe"
					x.Status.UserInfo.Groups = []string{"system:authenticated"}
					permissionReply(w, x)
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					x := authorization.SelfSubjectAccessReview{}
					x.Status.Allowed = true
					permissionReply(w, x)
				case "/apis/apps/v1/namespaces/owners/deployments/hub":
					if r.Method == http.MethodPut {
						if r.URL.Query().Get("dryRun") != "All" {
							t.Error("unsafe guard probe")
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(403)
						_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'owner-workload' with binding 'owner-workload' denied request: " + ownerWorkloadDenial}}}})
						return
					}
					p := v.deploy.DeepCopy()
					if mode == "wrong-deployment" && n > 0 {
						p.UID = types.UID(ownerID(99))
					}
					if mode == "scaled-down" {
						p.Spec.Replicas = ptr.To(int32(0))
					}
					if mode == "template-account" {
						p.Spec.Template.Spec.ServiceAccountName = "other"
					}
					permissionReply(w, p)
				case "/api/v1/namespaces/owners/serviceaccounts/hub":
					p := v.sa.DeepCopy()
					if mode == "wrong-live-account" {
						p.UID = types.UID(ownerID(99))
					}
					permissionReply(w, p)
				case "/api/v1/namespaces/owners/pods/owner-pod":
					p := v.pod.DeepCopy()
					switch mode {
					case "pending":
						p.Status.Phase = core.PodPending
						p.Status.Conditions = nil
					case "not-ready":
						p.Status.Conditions = nil
					case "status-change":
						if n == 2 {
							p.Status.Conditions = nil
							p.ResourceVersion = "changed-status"
						}
					case "wrong-owner":
						p.OwnerReferences[0].Kind = "Job"
					case "two-owners":
						p.OwnerReferences = append(p.OwnerReferences, p.OwnerReferences[0])
					case "wrong-selector":
						p.Labels = map[string]string{"app": "other"}
					case "unassigned":
						p.Spec.NodeName = ""
					case "host-network":
						p.Spec.HostNetwork = true
					case "host-pid":
						p.Spec.HostPID = true
					case "host-ipc":
						p.Spec.HostIPC = true
					case "injected-process":
						p.Spec.EphemeralContainers = []core.EphemeralContainer{{}}
					case "deleted-pod":
						p.DeletionTimestamp = &meta.Time{Time: start}
					case "failed-pod":
						p.Status.Phase = core.PodFailed
					case "spec-changed":
						if n == 2 {
							p.Spec.Hostname = "changed"
						}
					}
					permissionReply(w, p)
				case "/apis/apps/v1/namespaces/owners/replicasets/hub-rs":
					p := v.rs.DeepCopy()
					if mode == "wrong-replica" {
						p.UID = types.UID(ownerID(99))
					}
					permissionReply(w, p)
				case "/apis/authentication.k8s.io/v1/tokenreviews":
					n = reviews.Add(1)
					var req auth.TokenReview
					if json.NewDecoder(r.Body).Decode(&req) != nil || req.Spec.Token != string(token) || len(req.Spec.Audiences) != 1 || req.Spec.Audiences[0] != ConnectorEnrollmentAudience(v.pool.InstallationID) {
						t.Error("wrong enrollment token audience/request")
					}
					if mode == "token-error-redaction" {
						w.WriteHeader(500)
						_, _ = w.Write(token)
						return
					}
					reply := auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Status: auth.TokenReviewStatus{Authenticated: true, Audiences: req.Spec.Audiences, User: auth.UserInfo{Username: "system:serviceaccount:owners:hub", UID: v.pool.AccountUID, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {v.pod.Name}, "authentication.kubernetes.io/pod-uid": {v.binding.PodUID}}}}}
					switch mode {
					case "wrong-audience":
						reply.Status.Audiences = []string{DownloadPeerAudience(v.pool.InstallationID)}
					case "unbound":
						reply.Status.User.Extra = nil
					case "wrong-account":
						reply.Status.User.UID = ownerID(99)
					case "wrong-pod":
						reply.Status.User.Extra["authentication.kubernetes.io/pod-uid"] = auth.ExtraValue{ownerID(99)}
					case "path-pod":
						reply.Status.User.Extra["authentication.kubernetes.io/pod-name"] = auth.ExtraValue{"../secrets"}
					case "denied-review":
						reply.Status.Authenticated = false
					case "revoked-review":
						if n == 2 {
							reply.Status.Authenticated = false
						}
					case "late":
						if n == 2 {
							clock.Store(start.Add(5 * time.Second).UnixNano())
						}
					}
					permissionReply(w, reply)
				default:
					t.Error("unexpected identity/readiness lookup", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			// Match the names used by the bounded fake API; never resolve a Pod by
			// an endpoint or request-provided name during enrollment.
			v.pod.Name = "owner-pod"
			v.rs.Name = "hub-rs"
			v.pod.OwnerReferences[0].Name = v.rs.Name
			clientConfig := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			reader, e := NewPermissionClient(clientConfig, v.pool.ClusterID, plan.ControlNamespace, now)
			if e != nil {
				t.Fatal(e)
			}
			probe, e := NewPermissionClient(clientConfig, v.pool.ClusterID, plan.ControlNamespace, now)
			if e != nil {
				t.Fatal(e)
			}
			guard, e := NewOwnerWorkloadProtection(reader, probe, plan, pin)
			if e != nil {
				t.Fatal(e)
			}
			configuration := value.ConnectorCredentialProfile{RootID: ownerID(21), Binding: peer, Revision: identity.Revision{UID: ownerID(13), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", ClientIssuerRoots: [][]byte{{1, 2, 3}}, ServerIssuerRoots: [][]byte{{4, 5, 6}}, Deployment: value.ConnectorDeployment{Namespace: v.pool.Namespace, NamespaceUID: v.pool.NamespaceUID, ServiceAccount: v.pool.ServiceAccount, AccountUID: v.pool.AccountUID, Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, ServingSlots: 2, RetainedProcesses: 8}}
			configCalls := 0
			configurations := connectorSourceFunc(func(context.Context) (value.ConnectorIdentitySource, error) {
				configCalls++
				c := configuration.Clone()
				at, until := start, start.Add(5*time.Second)
				if mode == "configuration-unavailable" {
					return value.ConnectorIdentitySource{}, errors.New("synthetic unavailable")
				}
				if mode == "suspended" {
					c.Suspended = true
				}
				if mode == "configuration-changed" && configCalls > 1 {
					c.Revision.Generation++
				}
				if mode == "configuration-expired" {
					at = start.Add(-5 * time.Second)
					until = start
				}
				if mode == "cached-configuration" && configCalls == 1 {
					at = start.Add(-3 * time.Second)
					until = start.Add(2 * time.Second)
				}
				out := value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: c, ObservedAt: at, FreshUntil: until}, Roles: value.ConnectorIdentityRoles{Source: "connector_source", Journal: "connector_journal", Acknowledgement: "connector_ack", Cleanup: "connector_cleanup", Verifier: "connector_verifier", Finalizer: "connector_finalizer"}}
				if mode == "roles-changed" && configCalls > 1 {
					out.Roles.Source = "changed_source"
				}
				return out, nil
			})
			var owned []byte
			tokens := connectorTokenFunc(func(context.Context) ([]byte, error) {
				owned = bytes.Clone(token)
				if mode == "token-read-error" {
					return owned, errors.New(string(token))
				}
				return owned, nil
			})
			attester, e := NewConnectorProcessAttester(reader, configurations, guard, tokens)
			if e != nil {
				t.Fatal(e)
			}
			ctx, end := context.WithCancel(context.Background())
			defer end()
			if mode == "cancelled" {
				end()
			}
			var out value.ConnectorProcessProof
			if observation {
				var result value.ConnectorObservationAttestation
				result, e = attester.ReadConnectorObservationProof(ctx, request)
				out = result.Proof
				if e == nil && (result.Source.Roles.Source != "connector_source" || !result.Source.Observation.SameSource(out.Configuration) || configCalls != 2) {
					t.Fatal("observation source was reconstructed or reread")
				}
			} else {
				out, e = attester.ReadConnectorProcessProof(ctx, request)
			}
			positive := mode == "valid" || mode == "pending" || mode == "not-ready" || mode == "status-change" || mode == "short-token" || mode == "cached-configuration"
			if !positive {
				if e == nil {
					t.Fatal("invalid enrollment accepted")
				}
				if strings.Contains(e.Error(), string(token)) {
					t.Fatal("token leaked in error")
				}
				if out.Process != (value.ConnectorProcessIdentity{}) {
					t.Fatal("failed proof returned identity")
				}
			} else {
				if e != nil || !out.Valid(now()) || out.Process != request.Process || reviews.Load() != 2 {
					t.Fatal("valid enrollment failed", e)
				}
				want := start.Add(5 * time.Second)
				if mode == "short-token" {
					want = start.Add(time.Second)
				}
				if mode == "cached-configuration" {
					want = start.Add(2 * time.Second)
				}
				if !out.FreshUntil.Equal(want) || !out.ObservedAt.Equal(start) || out.Valid(want) {
					t.Fatal("proof renewed or ignored original deadline")
				}
				configuration.ClientIssuerRoots[0][0] = 9
				if out.Configuration.Profile.ClientIssuerRoots[0][0] != 1 {
					t.Fatal("proof aliases source roots")
				}
			}
			if len(owned) > 0 && !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("owned token buffer not cleared")
			}
			if (mode == "invalid-csr" || mode == "same-key") && calls.Load() != 0 {
				t.Fatal("invalid CSR/purpose reached API")
			}
		})
	}
}
