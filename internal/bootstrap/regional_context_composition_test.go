package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	auth "k8s.io/api/authentication/v1"
)

// Exercise the actual API-only constructor. Holder tests that construct their
// own output miss a later struct assignment discarding the node-free holder.
func TestRegionalAPIOnlyContextRetainsLogsHolder(t *testing.T) {
	c := regionalTestDeployment(t)
	if c.Collector != nil {
		t.Fatal("fixture unexpectedly enables node collection")
	}
	pod := "10000000-0000-4000-8000-000000000050"
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
			t.Errorf("unexpected constructor API call %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		v := auth.SelfSubjectReview{}
		v.Status.UserInfo.Extra = map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-uid": {pod}}
		_ = json.NewEncoder(w).Encode(v)
	}))
	defer server.Close()
	dir := t.TempDir()
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	for _, name := range []string{"kube-observer.token", "kube-probe.token"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte("synthetic-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	in := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	starts, err := ownerDeploymentStarts(&c.APIContext.Starts)
	if err != nil {
		t.Fatal(err)
	}
	workload := cfg.OwnerWorkloadAdministration{Name: c.WorkloadGuard.Name, Deployment: c.Deployment.Name, DeploymentUID: c.Deployment.UID, ControlNamespace: control, Administrators: regionalActors(c.WorkloadGuard.Administrators), APIContextStarts: starts, CredentialSecrets: []cfg.OwnerCredentialSecret{{Secret: c.ClusterCredential.Name, ServiceAccount: c.ClusterCredentialAccount}}}
	source := cfg.ConfigMapAdministration{Name: c.SourceGuard.Name, SourceName: c.Source.Name, ControlNamespace: control, Administrators: regionalActors(c.SourceGuard.Administrators)}
	binding := fleet.PeerBinding{InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, PeerID: c.PeerID, Role: fleet.ConnectorPeer}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	c.APIContext.TrustSettings = contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: c.PermissionRootID, InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{{ID: "synthetic-key", PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: n.Add(-time.Minute).Format(time.RFC3339Nano), NotAfter: n.Add(time.Hour).Format(time.RFC3339Nano)}}}
	built, closers, err := newRegionalContext(t.Context(), c, in, pod, workload, source, binding, &RegionalLifecycle{}, nil)
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	if err != nil {
		t.Fatal("actual API-only constructor", err)
	}
	if built.output.recordings == nil {
		t.Fatal("actual API-only constructor discarded logs holder")
	}
	h := built.output.recordings
	if built.logsClient == nil || h.pods != built.collector || h.nodes != nil || h.now == nil || built.output.store == nil || built.output.client == nil || built.output.now == nil {
		t.Fatal("incomplete node-free output composition")
	}
	if calls.Load() != 1 {
		t.Fatal("constructor added API work", calls.Load())
	}
}
