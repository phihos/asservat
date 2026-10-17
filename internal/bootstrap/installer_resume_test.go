package bootstrap

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestInstallerResumeUsesLocalKubeconfigContextAndNamespace(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(map[bool]string{false: "current-context", true: "explicit-overrides"}[override], func(t *testing.T) {
			calls := 0
			wantNamespace := "original-bootstrap"
			if override {
				wantNamespace = "selected-bootstrap"
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/"+wantNamespace+"/pods/original-bootstrap" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`))
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			config := clientapi.Config{CurrentContext: "original", Clusters: map[string]*clientapi.Cluster{"test": {Server: server.URL, CertificateAuthorityData: ca}}, AuthInfos: map[string]*clientapi.AuthInfo{"local": {}}, Contexts: map[string]*clientapi.Context{"original": {Cluster: "test", AuthInfo: "local", Namespace: "original-bootstrap"}, "selected": {Cluster: "test", AuthInfo: "local", Namespace: "other-bootstrap"}}}
			path := filepath.Join(t.TempDir(), "kubeconfig")
			if err := clientcmd.WriteToFile(config, path); err != nil {
				t.Fatal(err)
			}
			t.Setenv("KUBECONFIG", path)
			args := []string{"--name", "original"}
			wantContext := "original"
			if override {
				wantContext = "selected"
				t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
				args = append(args, "--kubeconfig", path, "--context", "selected", "--namespace", wantNamespace)
			}
			var output bytes.Buffer
			if err := RunInstallerResume(context.Background(), args, &output); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !strings.Contains(output.String(), `context "`+wantContext+`"`) || !strings.Contains(output.String(), `namespace "`+wantNamespace+`"`) || !strings.Contains(output.String(), "No runner is present") || strings.Contains(output.String(), "installation completed") {
				t.Fatal("wrong resolved target or absence claimed recovery", output.String(), calls)
			}
		})
	}
}

func TestInstallerResumeCannotFallBackToPodCredentialsOrGuessContext(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "not-present"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	for _, args := range [][]string{nil, {"--context", "missing"}, {"--force"}, {"unexpected-positional"}} {
		var output bytes.Buffer
		if RunInstallerResume(context.Background(), args, &output) == nil || output.Len() != 0 {
			t.Fatal("missing local selection used ambient Pod authority", args, output.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if RunInstallerResume(ctx, nil, &bytes.Buffer{}) == nil {
		t.Fatal("canceled request was admitted")
	}
}
