package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
)

func smallServicesHookTLS(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned secrets API root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func pemDER(t *testing.T, s string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("PEM")
	}
	return block.Bytes
}

// renderSecretsHook renders the chart and returns the hook's plan and Role.
func renderSecretsHook(t *testing.T, values map[string]any) (contracts.SecretsPlan, *rbac.Role, *batch.Job) {
	t.Helper()
	helm, e := exec.LookPath("helm")
	if e != nil {
		t.Skip("Helm is required")
	}
	input, _ := json.Marshal(values)
	path := filepath.Join(t.TempDir(), "values.json")
	if e = os.WriteFile(path, input, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	rendered, e := exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", path).CombinedOutput()
	if e != nil {
		t.Fatalf("actual Helm producer: %v\n%s", e, rendered)
	}
	var plan contracts.SecretsPlan
	var role *rbac.Role
	var binding *rbac.RoleBinding
	var job *batch.Job
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var doc json.RawMessage
		if e = decoder.Decode(&doc); e == io.EOF {
			break
		} else if e != nil {
			t.Fatal(e)
		}
		var head struct {
			Kind     string
			Metadata struct{ Name string }
		}
		if json.Unmarshal(doc, &head) != nil || head.Metadata.Name != "trial-secrets" {
			continue
		}
		switch head.Kind {
		case "Role":
			role = &rbac.Role{}
			e = json.Unmarshal(doc, role)
		case "RoleBinding":
			binding = &rbac.RoleBinding{}
			e = json.Unmarshal(doc, binding)
		case "Job":
			job = &batch.Job{}
			e = json.Unmarshal(doc, job)
		case "ConfigMap":
			var cm core.ConfigMap
			if e = json.Unmarshal(doc, &cm); e == nil {
				plan, e = contracts.DecodeSecretsPlan(strings.NewReader(cm.Data["secrets.json"]))
			}
		}
		if e != nil {
			t.Fatal("rendered hook object rejected", head.Kind, e)
		}
	}
	if role == nil || binding == nil || job == nil || binding.RoleRef.Name != role.Name || len(binding.Subjects) != 1 || binding.Subjects[0].Name != job.Spec.Template.Spec.ServiceAccountName {
		t.Fatal("secrets Job is not bound to the rendered Role")
	}
	return plan, role, job
}

// secretsAPI is a fake Kubernetes API that enforces the rendered Role.
type secretsAPI struct {
	mu       sync.Mutex
	t        *testing.T
	role     *rbac.Role
	secrets  map[string]*core.Secret
	creates  []string
	patches  []string
	denials  []string
	unknown  string
	external map[string]bool
}

func (a *secretsAPI) allowed(verb, name string) bool {
	for _, rule := range a.role.Rules {
		if slices.Contains(rule.APIGroups, "") && slices.Contains(rule.Resources, "secrets") && slices.Contains(rule.Verbs, verb) && (len(rule.ResourceNames) == 0 || slices.Contains(rule.ResourceNames, name)) {
			return true
		}
	}
	return false
}

func (a *secretsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	status := func(code int, reason string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "code": code, "reason": reason})
	}
	path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(path) < 5 || path[0] != "api" || path[1] != "v1" || path[2] != "namespaces" || path[3] != a.role.Namespace || path[4] != "secrets" || len(path) > 6 {
		a.t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
		status(403, "Forbidden")
		return
	}
	name := ""
	if len(path) == 6 {
		name = path[5]
	}
	verb := map[string]string{http.MethodGet: "get", http.MethodPost: "create", http.MethodPatch: "patch"}[r.Method]
	if verb == "" || !a.allowed(verb, name) {
		a.denials = append(a.denials, verb+" "+name)
		status(403, "Forbidden")
		return
	}
	switch verb {
	case "get":
		if s := a.secrets[name]; s != nil {
			_ = json.NewEncoder(w).Encode(s)
			return
		}
		status(404, "NotFound")
	case "create":
		var s core.Secret
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&s) != nil || s.Name == "" || s.Namespace != a.role.Namespace {
			status(400, "BadRequest")
			return
		}
		if a.secrets[s.Name] != nil {
			status(409, "AlreadyExists")
			return
		}
		if a.external[s.Name] {
			a.t.Errorf("created overridden Secret %s", s.Name)
		}
		if s.Name == "trial-postgres-state" && a.secrets["trial-keycloak-state"] == nil {
			a.t.Error("database material created before original realm/client identity")
		}
		s.UID = types.UID(fmt.Sprintf("99000000-0000-4000-8000-%012d", len(a.secrets)+1))
		s.ResourceVersion = "1"
		a.secrets[s.Name] = &s
		a.creates = append(a.creates, s.Name)
		if a.unknown == s.Name {
			a.unknown = ""
			status(500, "InternalError")
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(s)
	case "patch":
		s := a.secrets[name]
		var p struct {
			Data map[string][]byte `json:"data"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if s == nil || r.Header.Get("Content-Type") != "application/merge-patch+json" || d.Decode(&p) != nil || len(p.Data) == 0 {
			status(400, "BadRequest")
			return
		}
		for k, v := range p.Data {
			s.Data[k] = v
		}
		a.patches = append(a.patches, name)
		_ = json.NewEncoder(w).Encode(s)
	}
}

func (a *secretsAPI) snapshot() map[string]map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]map[string]string{}
	for name, s := range a.secrets {
		out[name] = map[string]string{}
		for k, v := range s.Data {
			out[name][k] = string(v)
		}
	}
	return out
}

func secretsHelmValues(mode string) map[string]any {
	values := smallServicesHelmValues(map[string]any{
		"postgres":    map[string]any{"provider": "bundled", "bundled": map[string]any{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}},
		"identity":    map[string]any{"provider": "keycloak", "keycloak": map[string]any{"hostname": "https://identity.example", "tlsSecretName": "operator-identity-tls", "mcpRedirectURIs": []string{"http://127.0.0.1:42000/callback"}}},
		"objectStore": map[string]any{"provider": "seaweedfs"},
		"keyService":  map[string]any{"provider": "openbao"},
	})
	values["mode"] = mode
	return values
}

// The rendered plan and Role drive the actual command against a fake API.
func TestSecretsHookUsesRenderedPlanAndExactRole(t *testing.T) {
	for _, mode := range []string{"hub", "combined"} {
		t.Run(mode, func(t *testing.T) {
			plan, role, job := renderSecretsHook(t, secretsHelmValues(mode))
			if job.Spec.BackoffLimit == nil || job.Spec.TTLSecondsAfterFinished == nil || job.Annotations["helm.sh/hook"] != "pre-install,pre-upgrade" || job.Annotations["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" {
				t.Fatal("secrets hook is not a bounded pre-install/pre-upgrade Job")
			}
			if c := job.Spec.Template.Spec.Containers; len(c) != 1 || !slices.Equal(c[0].Command, []string{"/asservat", "secrets"}) {
				t.Fatal("secrets Job does not run `asservat secrets`")
			}
			api := &secretsAPI{t: t, role: role, secrets: map[string]*core.Secret{}, unknown: "trial-sql-hub-api"}
			cert, ca := smallServicesHookTLS(t)
			server := httptest.NewUnstartedServer(api)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			config := &rest.Config{Host: server.URL, BearerToken: "synthetic", TLSClientConfig: rest.TLSClientConfig{CAData: []byte(ca)}}
			kubeAPI := contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: [][]byte{pemDER(t, ca)}}
			if e := runSecrets(t.Context(), plan, config, kubeAPI); e != nil {
				t.Fatalf("fresh run: %v; denied=%v", e, api.denials)
			}
			want := []string{"trial-keycloak-state", "trial-postgres-state", "trial-objectstore-state", "trial-openbao-state", "trial-ids",
				"trial-sql-hub-api", "trial-sql-hub-worker", "trial-sql-federation", "trial-sql-publisher", "trial-sql-key-service", "trial-audit-mac", "trial-artifact-key"}
			for _, p := range contracts.ObjectStorePrincipals(mode) {
				want = append(want, "trial-s3-"+p)
			}
			want = append(want, "trial-objectstore-iam")
			if !slices.Equal(api.creates, want) || len(api.patches) != 0 {
				t.Fatalf("creates=%v patches=%v", api.creates, api.patches)
			}
			first := api.snapshot()
			ids := first["trial-ids"]
			if len(ids) != len(contracts.InstallationIDKeys()) {
				t.Fatal("IDs Secret keys", ids)
			}
			for _, component := range contracts.SQLComponents() {
				purposes, _ := contracts.SQLComponentPurposes(component)
				data := first["trial-sql-"+component]
				if len(data) != len(purposes) {
					t.Fatalf("%s keys=%d want %d", component, len(data), len(purposes))
				}
				for _, purpose := range purposes {
					c, e := contracts.DecodeOwnerSQLCredential(strings.NewReader(data["sql-"+purpose+".json"]))
					name, _ := sqlRoleName(ids["installationID"], purpose)
					if e != nil || c.Username != name || len(c.Password) < 40 {
						t.Fatal("invalid SQL credential", component, purpose)
					}
				}
			}
			if len(first["trial-audit-mac"][contracts.AuditMACInputKey]) != 32 || !strings.Contains(first["trial-artifact-key"][contracts.ArtifactKeyFile], `"purpose":"artifact"`) {
				t.Fatal("audit MAC or artifact key material")
			}
			iam := first["trial-objectstore-iam"][providerconfig.SeaweedConfigKey]
			for _, p := range contracts.ObjectStorePrincipals(mode) {
				var c contracts.OwnerStorageCredential
				if json.Unmarshal([]byte(first["trial-s3-"+p][contracts.ObjectStoreCredentialFile]), &c) != nil || !strings.Contains(iam, c.AccessKeyID) {
					t.Fatal("IAM lacks principal", p)
				}
			}
			// A rerun (helm upgrade) changes nothing.
			if e := runSecrets(t.Context(), plan, config, kubeAPI); e != nil {
				t.Fatalf("rerun: %v; denied=%v", e, api.denials)
			}
			if len(api.creates) != len(want) || len(api.patches) != 0 || fmt.Sprint(api.snapshot()) != fmt.Sprint(first) {
				t.Fatal("rerun rotated or rewrote a Secret")
			}
			// A missing key (a new purpose after upgrade) is added; others stay.
			api.mu.Lock()
			delete(api.secrets["trial-sql-publisher"].Data, "sql-context-publish.json")
			api.mu.Unlock()
			if e := runSecrets(t.Context(), plan, config, kubeAPI); e != nil {
				t.Fatal(e)
			}
			after := api.snapshot()
			if !slices.Equal(api.patches, []string{"trial-sql-publisher"}) || after["trial-sql-publisher"]["sql-publication-gate.json"] != first["trial-sql-publisher"]["sql-publication-gate.json"] || after["trial-sql-publisher"]["sql-context-publish.json"] == "" {
				t.Fatal("missing key not added in place", api.patches)
			}
			if len(api.denials) != 0 {
				t.Fatal("rendered Role denied a request", api.denials)
			}
		})
	}
}

// existingSecret overrides are neither created nor patched; the IDs override
// is only read.
func TestSecretsHookHonoursExistingSecretOverrides(t *testing.T) {
	values := secretsHelmValues("hub")
	values["secrets"] = map[string]any{"ids": map[string]any{"existingSecret": "operator-ids"}, "sql-hub-api": map[string]any{"existingSecret": "operator-hub-sql"}, "artifact-key": map[string]any{"existingSecret": "operator-artifact"}}
	plan, role, _ := renderSecretsHook(t, values)
	if plan.IDs.Secret != "operator-ids" || plan.IDs.Generate || plan.ArtifactKey != "" || slices.ContainsFunc(plan.SQL, func(s contracts.SecretsSQL) bool { return s.Component == "hub-api" }) {
		t.Fatal("overrides not reflected in plan", plan)
	}
	ids := map[string][]byte{}
	for i, key := range contracts.InstallationIDKeys() {
		ids[key] = fmt.Appendf(nil, "10000000-0000-4000-8000-%012d", i+1)
	}
	api := &secretsAPI{t: t, role: role, secrets: map[string]*core.Secret{"operator-ids": {Data: ids}}, external: map[string]bool{"operator-hub-sql": true, "operator-artifact": true}}
	cert, ca := smallServicesHookTLS(t)
	server := httptest.NewUnstartedServer(api)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic", TLSClientConfig: rest.TLSClientConfig{CAData: []byte(ca)}}
	if e := runSecrets(t.Context(), plan, config, contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: [][]byte{pemDER(t, ca)}}); e != nil {
		t.Fatalf("%v; denied=%v", e, api.denials)
	}
	if slices.Contains(api.creates, "trial-ids") || len(api.patches) != 0 || !strings.Contains(string(api.secrets["trial-sql-hub-worker"].Data["sql-permission-accept.json"]), "as_10000000000040008000000000000001_pub_") {
		t.Fatal("override IDs not used", api.creates)
	}
}
