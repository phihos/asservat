package bootstrap

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestMixedProviderCLIUsesRetainedInputsWithoutCredentialFiles(t *testing.T) {
	for _, scenario := range []string{"positive", "ambiguous-files", "wrong-recipe", "unknown-mode", "private-keyservice-mode"} {
		t.Run(scenario, func(t *testing.T) {
			installation := "10000000-0000-4000-8000-000000000001"
			artifact := []byte(`{"apply":[{"method":"POST","path":"sys/policies/acl/asservat-synthetic-worker","body":{"policy":"path \"synthetic\" { capabilities = [\"read\"] }"}}],"inspect":["sys/policies/acl/asservat-synthetic-worker"]}`)
			mode := contracts.InstallerProviderBundledObjectStore
			if scenario == "unknown-mode" {
				mode = "unknown"
			}
			if scenario == "private-keyservice-mode" {
				mode = contracts.InstallerProviderBundledKeyService
			}
			outbox := contracts.InstallerRecipeOutbox{Format: contracts.InstallerRecipeOutboxFormat, Phase: 1, Purpose: "worker-provider", ProviderMode: mode, Recipe: artifact}
			rawOutbox, _ := json.Marshal(outbox)
			credential := []byte(`{"accessKeyID":"ASV0011223344556677889900112233445566778899","secretAccessKey":"0011223344556677889900112233445566778899001122334455667788990011","sessionToken":""}`)
			digest := installerRecipeDigest(artifact)
			if scenario == "wrong-recipe" {
				digest = strings.Repeat("f", 64)
			}
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: contracts.InstallerInboxName(installation), Namespace: "bootstrap", UID: types.UID(initialBaoState), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "bundled-installer-inbox"}, Annotations: map[string]string{"asservat.io/provider-recipe-sha256": digest, "asservat.io/provider-mode": contracts.InstallerProviderBundledObjectStore}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.InstallerInboxPhase: []byte("1"), contracts.InstallerInboxAuditCredential: bytes.Clone(credential)}}
			providerCalls, providerWrites, tokenCreates, inboxReads, inboxWrites := 0, 0, 0, 0, 0
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls++
				if r.Header.Get("X-Vault-Token") != "synthetic-external-provider-administrator" {
					t.Error("external administration token missing")
					w.WriteHeader(403)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/asservat-"):
					w.WriteHeader(404)
					_, _ = io.WriteString(w, `{"errors":[]}`)
				case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/asservat-"):
					providerWrites++
					w.WriteHeader(204)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/create":
					tokenCreates++
					_, _ = io.WriteString(w, `{"auth":{"client_token":"synthetic-finite-inspection"}}`)
				default:
					t.Error("unexpected provider path")
					w.WriteHeader(403)
				}
			}))
			defer provider.Close()
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer synthetic-original-installer" {
					t.Error("original native identity lost")
					w.WriteHeader(403)
					return
				}
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configmaps/"+contracts.InstallerRecipeOutboxName(installation)):
					_ = json.NewEncoder(w).Encode(core.ConfigMap{Data: map[string]string{"outbox.json": string(rawOutbox)}})
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+contracts.InstallerInboxName(installation)):
					inboxReads++
					_ = json.NewEncoder(w).Encode(secret)
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/secrets/"+contracts.InstallerInboxName(installation)):
					inboxWrites++
					var next core.Secret
					if json.NewDecoder(r.Body).Decode(&next) != nil {
						t.Error("invalid inbox update")
						w.WriteHeader(400)
						return
					}
					oldData, newData := maps.Clone(secret.Data), maps.Clone(next.Data)
					delete(oldData, contracts.InstallerInboxInspectionToken)
					delete(newData, contracts.InstallerInboxInspectionToken)
					if !maps.EqualFunc(oldData, newData, bytes.Equal) || next.UID != secret.UID || next.ResourceVersion != secret.ResourceVersion {
						t.Error("provider-only operation replaced original inputs")
						w.WriteHeader(409)
						return
					}
					next.ResourceVersion = "2"
					secret = next
					_ = json.NewEncoder(w).Encode(secret)
				default:
					t.Errorf("unexpected Kubernetes method %s", r.Method)
					w.WriteHeader(403)
				}
			}))
			defer api.Close()
			dir := t.TempDir()
			providerCA := filepath.Join(dir, "provider-ca.pem")
			if os.WriteFile(providerCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0600) != nil {
				t.Fatal("write provider CA")
			}
			t.Setenv("BAO_ADDR", provider.URL)
			t.Setenv("BAO_CACERT", providerCA)
			t.Setenv("BAO_TOKEN", "synthetic-external-provider-administrator")
			config := clientapi.Config{CurrentContext: "original", Clusters: map[string]*clientapi.Cluster{"original": {Server: api.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})}}, AuthInfos: map[string]*clientapi.AuthInfo{"original": {Token: "synthetic-original-installer"}}, Contexts: map[string]*clientapi.Context{"original": {Cluster: "original", AuthInfo: "original", Namespace: "bootstrap"}}}
			path := filepath.Join(dir, "kubeconfig")
			if err := clientcmd.WriteToFile(config, path); err != nil {
				t.Fatal(err)
			}
			args := []string{"--kubeconfig", path, "--context", "original", "--namespace", "bootstrap", "--installation", installation}
			if scenario == "ambiguous-files" {
				args = append(args, "--audit-credential", filepath.Join(dir, "must-not-read"))
			}
			var output bytes.Buffer
			err := RunInstallerProviderApply(t.Context(), args, &output)
			if scenario != "positive" {
				if err == nil || providerCalls != 0 || inboxWrites != 0 {
					t.Fatal("invalid selected handoff reached provider mutation", err, providerCalls, inboxWrites)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if providerWrites != 2 || tokenCreates != 1 || inboxWrites != 1 || inboxReads != 2 || !bytes.Equal(credential, secret.Data[contracts.InstallerInboxAuditCredential]) || string(secret.Data[contracts.InstallerInboxInspectionToken]) != "synthetic-finite-inspection" {
				t.Fatal("real CLI failed to complete only original inspection", providerWrites, tokenCreates, inboxWrites, inboxReads)
			}
			for _, private := range []string{string(credential), "synthetic-finite-inspection", "synthetic-external-provider-administrator"} {
				if bytes.Contains(output.Bytes(), []byte(private)) {
					t.Fatal("private material in CLI output")
				}
			}
			if !strings.Contains(output.String(), "Original inbox inspection completed") {
				t.Fatal(fmt.Errorf("missing observable handoff result"))
			}
		})
	}
}
