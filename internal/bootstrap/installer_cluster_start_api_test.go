package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

// Helm/operator management owns the CRD. The CLI must discover its required
// served API before creating any regional installation object. The fake API
// deliberately stops at Namespace CREATE; passing preflight is not a successful
// installation or a claim that discovery qualified the CRD's schema.
func TestInstallerClusterRequiresStartAPIBeforeMutation(t *testing.T) {
	for _, scenario := range []string{
		"missing-api", "missing-main", "missing-status", "wrong-group-version",
		"wrong-kind", "cluster-scoped", "missing-create", "missing-get",
		"missing-status-update", "duplicate-main", "duplicate-status", "status-cluster-scoped",
		"wrong-resource-group", "wrong-resource-version", "too-many-resources", "malformed", "trailing-data",
		"oversized-body", "oversized-error-body", "retry-after", "caller-cancellation", "caller-deadline", "ready", "plain-connector",
	} {
		t.Run(scenario, func(t *testing.T) {
			resources := meta.APIResourceList{
				TypeMeta:     meta.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
				GroupVersion: "asservat.io/v1alpha1",
				APIResources: []meta.APIResource{
					{Name: "capacityreservations", SingularName: "capacityreservation", Namespaced: true, Kind: "CapacityReservation", Verbs: meta.Verbs{"create", "get"}},
					{Name: "capacityreservations/status", Namespaced: true, Kind: "CapacityReservation", Verbs: meta.Verbs{"get", "update"}},
				},
			}
			switch scenario {
			case "missing-main":
				resources.APIResources = resources.APIResources[1:]
			case "missing-status":
				resources.APIResources = resources.APIResources[:1]
			case "wrong-group-version":
				resources.GroupVersion = "other.invalid/v1alpha1"
			case "wrong-kind":
				resources.APIResources[0].Kind = "Other"
			case "cluster-scoped":
				resources.APIResources[0].Namespaced = false
			case "missing-create":
				resources.APIResources[0].Verbs = meta.Verbs{"get"}
			case "missing-get":
				resources.APIResources[0].Verbs = meta.Verbs{"create"}
			case "missing-status-update":
				resources.APIResources[1].Verbs = meta.Verbs{"get"}
			case "duplicate-main":
				resources.APIResources = append(resources.APIResources, resources.APIResources[0])
			case "duplicate-status":
				resources.APIResources = append(resources.APIResources, resources.APIResources[1])
			case "status-cluster-scoped":
				resources.APIResources[1].Namespaced = false
			case "wrong-resource-group":
				resources.APIResources[0].Group = "other.invalid"
			case "wrong-resource-version":
				resources.APIResources[1].Version = "v2"
			case "too-many-resources":
				for len(resources.APIResources) <= 256 {
					resources.APIResources = append(resources.APIResources, meta.APIResource{Name: "unrelated"})
				}
			}
			encoded, err := json.Marshal(resources)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "malformed":
				encoded = []byte("{")
			case "trailing-data":
				encoded = append(encoded, []byte(`{}`)...)
			case "oversized-body":
				encoded = append(bytes.Repeat([]byte(" "), 256<<10), encoded...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if scenario == "caller-deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			var discoveries, mutations atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					_, _ = w.Write([]byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","status":{"userInfo":{"username":"synthetic-operator"}}}`))
				case r.Method == http.MethodGet && r.URL.Path == "/apis/asservat.io/v1alpha1":
					discoveries.Add(1)
					if scenario == "missing-api" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"private-provider-detail"}`))
						return
					}
					if scenario == "oversized-error-body" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write(bytes.Repeat([]byte(" "), 256<<10))
						_ = http.NewResponseController(w).Flush()
						// A bounded error-body reader closes before this original
						// one-second request expires, without needing EOF.
						<-r.Context().Done()
						return
					}
					if scenario == "retry-after" {
						w.Header().Set("Retry-After", "1")
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"TooManyRequests","code":429}`))
						return
					}
					if scenario == "caller-cancellation" || scenario == "caller-deadline" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte("{"))
						_ = http.NewResponseController(w).Flush()
						if scenario == "caller-cancellation" {
							cancel()
						}
						<-r.Context().Done()
						return
					}
					_, _ = w.Write(encoded)
				default:
					if r.Method != http.MethodGet && r.Method != http.MethodHead {
						mutations.Add(1)
					}
					if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces" {
						t.Errorf("unexpected installation request %s %s", r.Method, r.URL.Path)
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"ServiceUnavailable","code":503,"message":"private-provider-detail"}`))
				}
			}))
			defer server.Close()
			args := installerClusterStartAPIArgs(t, server, scenario != "plain-connector")
			var output bytes.Buffer
			started := time.Now()
			err = RunInstallerCluster(ctx, args, &output)
			if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-provider-detail") {
				t.Fatal("failed fixture disclosed output or provider detail", err, output.String())
			}
			if scenario == "ready" || scenario == "plain-connector" {
				wantDiscovery := int32(1)
				if scenario == "plain-connector" {
					wantDiscovery = 0
				}
				if discoveries.Load() != wantDiscovery || mutations.Load() != 1 || !strings.Contains(err.Error(), "stopped at namespace:") {
					t.Fatalf("available prerequisite did not reach existing namespace step: discovery=%d mutations=%d error=%v", discoveries.Load(), mutations.Load(), err)
				}
				return
			}
			if discoveries.Load() != 1 || mutations.Load() != 0 || !strings.Contains(err.Error(), "stopped at start-api:") {
				t.Fatalf("missing/incorrect start API did not stop before mutation: discovery=%d mutations=%d error=%v", discoveries.Load(), mutations.Load(), err)
			}
			if scenario == "caller-cancellation" || scenario == "caller-deadline" {
				if ctx.Err() == nil || time.Since(started) > 500*time.Millisecond {
					t.Fatal("discovery escaped original cancellation/deadline", ctx.Err(), time.Since(started))
				}
			}
			if scenario == "oversized-error-body" || scenario == "retry-after" {
				if ctx.Err() != nil || time.Since(started) > 500*time.Millisecond {
					t.Fatal("discovery waited for an unbounded error body or retried", ctx.Err(), time.Since(started))
				}
			}
		})
	}
}

func installerClusterStartAPIArgs(t *testing.T, server *httptest.Server, executor bool) []string {
	t.Helper()
	dir := t.TempDir()
	id := func(suffix string) string { return "10000000-0000-4000-8000-0000000000" + suffix }
	offer := contracts.RegionalOffer{
		Format: contracts.RegionalOfferFormat, InstallationID: id("01"), PermissionRootID: id("02"), IssuerEpoch: id("03"),
		Image:                "registry.invalid/asservat@sha256:" + strings.Repeat("ab", 32),
		Federation:           contracts.RegionalHubEndpoint{Endpoint: "https://federation.invalid", ServerName: "federation.invalid", Roots: [][]byte{{1}}},
		ConnectorIssuerRoots: [][]byte{{2}}, ConnectorBacking: json.RawMessage(`{}`),
	}
	if executor {
		offer.Owners = &contracts.RegionalContextOwners{}
		offer.KeyService = &contracts.RegionalWrapService{KeyID: "artifact"}
		offer.WorkKey = &contracts.APIContextWorkPublicKey{ID: "work-v1"}
		offer.EvidenceStore = &contracts.RegionalEvidenceStore{StoreID: id("04")}
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	record := map[string]any{
		"binding": map[string]string{
			"format": "asservat-bootstrap-secret/v1", "installationID": offer.InstallationID,
			"bootstrapID": id("05"), "clusterID": id("06"), "peerID": id("07"), "issuerEpoch": offer.IssuerEpoch,
			"deliveryProfile": "regional-installer", "requestSHA256": strings.Repeat("01", 32),
			"notBefore": now.Format(time.RFC3339Nano), "notAfter": now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		},
		"secret": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config := clientapi.Config{
		CurrentContext: "region",
		Clusters:       map[string]*clientapi.Cluster{"region": {Server: server.URL, CertificateAuthorityData: ca}},
		AuthInfos:      map[string]*clientapi.AuthInfo{"operator": {}},
		Contexts:       map[string]*clientapi.Context{"region": {Cluster: "region", AuthInfo: "operator"}},
	}
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := clientcmd.WriteToFile(config, kubeconfig); err != nil {
		t.Fatal(err)
	}
	args := []string{"--kubeconfig", kubeconfig, "--offer", writeJSON("offer.json", offer), "--bootstrap", writeJSON("bootstrap.json", record)}
	if executor {
		args = append(args, "--evidence-credential", writeJSON("evidence.json", map[string]string{"accessKeyID": "synthetic", "secretAccessKey": "synthetic-secret", "sessionToken": ""}))
		args = append(args, "--history-credential", writeJSON("history.json", map[string]string{"accessKeyID": "synthetic-history", "secretAccessKey": "synthetic-history-secret", "sessionToken": ""}))
	}
	return args
}
