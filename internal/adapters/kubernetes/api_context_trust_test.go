package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-180: the hub reads a workload cluster's work trust from its own control
// namespace; the trust names that cluster and its keys, never the reader's.
// Real loopback TLS; admission replies, recovery and clock are synthetic.
func TestAPIContextWorkTrustIsHubHeldForAWorkloadCluster(t *testing.T) {
	for _, mode := range []string{"hub-held", "changed"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			installed := contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: ownerID(1), InstallationID: ownerID(2), ClusterID: ownerID(10), IssuerEpoch: ownerID(3), Revision: 1, Enabled: true,
				Keys: []contracts.APIContextWorkPublicKey{{ID: "hub-work", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), NotBefore: now.Add(-time.Hour).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano)}}}
			raw, err := contracts.EncodeAPIContextTrust(installed)
			if err != nil {
				t.Fatal(err)
			}
			served := string(raw)
			if mode == "changed" {
				changed := installed
				changed.Revision = 2
				b, _ := contracts.EncodeAPIContextTrust(changed)
				served = string(b)
			}
			plan := cfg.ConfigMapAdministration{Name: "trust-guard", ControlNamespace: permissionControl, SourceName: "api-context-work-trust", Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "admin"}}}
			p, b, err := APIContextWorkTrustAdmission(plan)
			if err != nil {
				t.Fatal(err)
			}
			p.UID, p.Generation, p.ResourceVersion = "policy", 1, "1"
			p.Status.ObservedGeneration = 1
			p.Status.TypeChecking = &admission.TypeChecking{}
			b.UID, b.ResourceVersion = "binding", "1"
			clock := &atomic.Int64{}
			clock.Store(now.UnixNano())
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
					permissionReply(w, p.DeepCopy())
				case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
					permissionReply(w, b)
				case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
					permissionReply(w, authn.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authn.SelfSubjectReviewStatus{UserInfo: authn.UserInfo{Username: "outsider", Groups: []string{"authenticated"}}}})
				case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
					permissionReply(w, authz.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: authz.SubjectAccessReviewStatus{Allowed: true}})
				case strings.HasSuffix(r.URL.Path, "/configmaps/api-context-work-trust"):
					if r.Method == "PUT" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(422)
						permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'trust-guard' with binding 'trust-guard' denied request: " + apiContextTrustDenial}}}})
						return
					}
					permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": true, "metadata": map[string]any{"name": "api-context-work-trust", "namespace": permissionControl.Name, "uid": ownerID(7), "resourceVersion": "1"}, "data": map[string]string{"api-context-work-trust.json": served}})
				case r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name:
					permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
				default:
					t.Error("unexpected API path", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			clockNow := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			observer, err := NewPermissionClient(config, permissionCluster, permissionControl, clockNow)
			if err != nil {
				t.Fatal(err)
			}
			probe, err := NewPermissionClient(config, permissionCluster, permissionControl, clockNow)
			if err != nil {
				t.Fatal(err)
			}
			guard, err := NewAPIContextWorkTrustProtection(observer, probe, plan, GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "1"})
			if err != nil {
				t.Fatal(err)
			}
			source, err := NewAPIContextWorkTrustSource(observer, guard, &capabilityRecovery{clock: clock}, "api-context-work-trust", ownerID(7), installed)
			if err != nil {
				t.Fatal("hub-held trust of another cluster refused", err)
			}
			got, err := source.APIContextWorkTrust(context.Background())
			if mode == "changed" {
				if err == nil {
					t.Fatal("changed trust accepted")
				}
				return
			}
			if err != nil || got.ClusterID != ownerID(10) || len(got.Trust.Keys) != 1 || got.Trust.Keys[0].ClusterID != ownerID(10) || !got.Valid(clockNow()) {
				t.Fatal("hub-held trust", err, got.ClusterID)
			}
		})
	}
}
