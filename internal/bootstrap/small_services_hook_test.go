package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"github.com/google/go-cmp/cmp"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func smallServicesHookTLS(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned preparation API root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
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

// This fake API enforces the actual rendered namespace Role. It does not use
// cluster-admin, grant missing rules, execute SQL or start provider services.
func TestSmallServicesHookUsesRenderedPlanAndExactRole(t *testing.T) {
	for _, bundledKeys := range []bool{false, true} {
		t.Run(fmt.Sprintf("bundled-keys-%t", bundledKeys), func(t *testing.T) {
			smallServicesRenderedHook(t, bundledKeys)
		})
	}
}

func smallServicesRenderedHook(t *testing.T, bundledKeys bool) {
	t.Helper()
	helm, e := exec.LookPath("helm")
	if e != nil {
		t.Skip("Helm is required")
	}
	values := map[string]any{"bootstrap": smallServicesHelmBootstrap(), "services": map[string]any{
		"postgres":    map[string]any{"provider": "bundled", "bundled": map[string]any{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}},
		"identity":    map[string]any{"provider": "keycloak", "keycloak": map[string]any{"hostname": "https://identity.example", "tlsSecretName": "operator-identity-tls", "mcpRedirectURIs": []string{"http://127.0.0.1:42000/callback"}}},
		"objectStore": map[string]any{"provider": "seaweedfs"},
	}}
	if bundledKeys {
		values["services"].(map[string]any)["keyService"] = map[string]any{"provider": "openbao"}
	}
	input, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	valuesPath := filepath.Join(t.TempDir(), "values.json")
	if e = os.WriteFile(valuesPath, input, 0600); e != nil {
		t.Fatal(e)
	}
	renderCtx, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	rendered, e := exec.CommandContext(renderCtx, helm, "template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", valuesPath).CombinedOutput()
	if e != nil {
		t.Fatalf("actual Helm producer: %v\n%s", e, rendered)
	}
	const name = "trial-services-prepare"
	var plan contracts.SmallServicesPreparation
	var role *rbac.Role
	var binding *rbac.RoleBinding
	var pod *core.Pod
	var public *core.ConfigMap
	var bootstrapPublic *core.ConfigMap
	var bootstrapPod *core.Pod
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var doc json.RawMessage
		e = decoder.Decode(&doc)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		var head struct {
			Kind     string
			Metadata struct{ Name string }
		}
		if json.Unmarshal(doc, &head) != nil {
			t.Fatal("chart JSON")
		}
		if head.Metadata.Name != name {
			if head.Kind == "ConfigMap" {
				var cm core.ConfigMap
				if json.Unmarshal(doc, &cm) != nil {
					t.Fatal("bootstrap public ConfigMap decode")
				}
				if cm.Data["bootstrap.json"] != "" {
					if bootstrapPublic != nil {
						t.Fatal("duplicate bootstrap input producer")
					}
					bootstrapPublic = &cm
				}
			}
			if head.Kind == "Pod" && head.Metadata.Name == "trial-bootstrap" {
				bootstrapPod = &core.Pod{}
				if json.Unmarshal(doc, bootstrapPod) != nil {
					t.Fatal("bootstrap runner Pod decode")
				}
			}
			continue
		}
		switch head.Kind {
		case "Role":
			role = &rbac.Role{}
			e = json.Unmarshal(doc, role)
		case "RoleBinding":
			binding = &rbac.RoleBinding{}
			e = json.Unmarshal(doc, binding)
		case "Pod":
			pod = &core.Pod{}
			e = json.Unmarshal(doc, pod)
		case "ConfigMap":
			public = &core.ConfigMap{}
			e = json.Unmarshal(doc, public)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if role == nil || binding == nil || pod == nil || public == nil || binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != role.Name || binding.Namespace != role.Namespace || len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Name != pod.Spec.ServiceAccountName || binding.Subjects[0].Namespace != pod.Namespace {
		t.Fatal("preparation consumer is not bound to rendered Role")
	}
	plan, e = contracts.DecodeSmallServicesPreparation(strings.NewReader(public.Data["preparation.json"]))
	if e != nil {
		t.Fatal("actual chart preparation.json rejected by closed production decoder", e)
	}
	if !plan.Postgres || plan.Keycloak == nil || plan.ObjectStore == nil || (plan.OpenBao != nil) != bundledKeys {
		t.Fatal("chart did not select the requested real preparation adapters")
	}
	// Compare the complete actual runner before changing any transport input.
	if bootstrapPublic == nil || bootstrapPod == nil {
		t.Fatal("missing public bootstrap input/runner")
	}
	initial, e := contracts.DecodeInitialBootstrapInput(strings.NewReader(bootstrapPublic.Data["bootstrap.json"]))
	if e != nil {
		t.Fatal("actual initial bootstrap wire", e)
	}
	refs, e := contracts.DecodeInitialBootstrapRunnerInput(strings.NewReader(bootstrapPublic.Data["runner.json"]))
	if e != nil {
		t.Fatal("actual bootstrap runner wire", e)
	}
	if refs.KeycloakSecret != "trial-keycloak-state" || refs.PostgresSecret != "trial-postgres-state" || initial.IdentitySource != "bundledKeycloak" {
		t.Fatal("runner omitted selected private-state references/public identity source")
	}
	digest := sha256.Sum256([]byte(bootstrapPublic.Data["bootstrap.json"] + "\n" + bootstrapPublic.Data["runner.json"]))
	expectedRunner, e := kube.BuildInitialBootstrapRunner(kube.InitialBootstrapRunnerPlan{Namespace: initial.BootstrapNamespace, Name: initial.Name, Image: initial.Image, InputDigest: hex.EncodeToString(digest[:]), ProducerSecret: refs.ProducerSecret, SchemaSecret: refs.SchemaSecret, RetirementSecret: refs.RetirementSecret, RegistrySecret: refs.RegistrySecret, ProbeAudience: initial.ProbeAudience, ContinuationDigest: refs.ContinuationDigest, PostgresSecret: refs.PostgresSecret, KeycloakSecret: refs.KeycloakSecret, ObjectStoreSecret: refs.ObjectStoreSecret, KeyServiceSecret: refs.KeyServiceSecret})
	if e != nil {
		t.Fatal("actual native runner builder", e)
	}
	a, _ := json.Marshal(bootstrapPod)
	b, _ := json.Marshal(expectedRunner)
	if !bytes.Equal(a, b) {
		t.Fatalf("actual Helm/native runner mismatch: %s", cmp.Diff(expectedRunner, bootstrapPod))
	}
	var mu sync.Mutex
	secrets := map[string]*core.Secret{}
	var creates, requests, denials []string
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range secrets {
			for _, b := range s.Data {
				clear(b)
			}
		}
	})
	allowed := func(group, resource, verb, object string) bool {
		for _, rule := range role.Rules {
			if !slices.Contains(rule.APIGroups, group) || !slices.Contains(rule.Resources, resource) || !slices.Contains(rule.Verbs, verb) {
				continue
			}
			if len(rule.ResourceNames) == 0 || slices.Contains(rule.ResourceNames, object) {
				return true
			}
		}
		return false
	}
	cert, ca := smallServicesHookTLS(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		status := func(code int, reason string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "code": code, "reason": reason})
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-preparation-token" {
			t.Error("preparation lost its actual mounted token transport")
			status(401, "Unauthorized")
			return
		}
		path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		group, offset := "", 0
		switch {
		case len(path) >= 5 && path[0] == "api" && path[1] == "v1" && path[2] == "namespaces":
			offset = 3
		case len(path) >= 6 && path[0] == "apis" && path[1] == "apps" && path[2] == "v1" && path[3] == "namespaces":
			group, offset = "apps", 4
		default:
			t.Error("unexpected preparation API path")
			status(403, "Forbidden")
			return
		}
		if path[offset] != role.Namespace || len(path) < offset+2 || len(path) > offset+3 {
			t.Error("preparation crossed namespace or subresource")
			status(403, "Forbidden")
			return
		}
		resource, object := path[offset+1], ""
		if len(path) == offset+3 {
			object = path[offset+2]
		}
		verb := ""
		if r.Method == http.MethodGet {
			verb = "get"
		}
		if r.Method == http.MethodPost {
			verb = "create"
		}
		step := verb + " " + resource + "/" + object
		requests = append(requests, step)
		if verb == "" || !allowed(group, resource, verb, object) {
			denials = append(denials, step)
			status(403, "Forbidden")
			return
		}
		if verb == "get" {
			if resource == "secrets" {
				if secret := secrets[object]; secret != nil {
					_ = json.NewEncoder(w).Encode(secret)
					return
				}
			}
			status(404, "NotFound")
			return
		}
		if resource != "secrets" || object != "" {
			t.Error("unexpected preparation mutation")
			status(403, "Forbidden")
			return
		}
		var secret core.Secret
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&secret) != nil || secret.Namespace != role.Namespace || secret.Name == "" {
			t.Error("invalid private Secret request")
			status(400, "BadRequest")
			return
		}
		if secrets[secret.Name] != nil {
			status(409, "AlreadyExists")
			return
		}
		if secret.Name == "trial-postgres-state" && secrets["trial-keycloak-state"] == nil {
			t.Error("database material created before original realm/client identity")
			status(400, "BadRequest")
			return
		}
		secret.UID = types.UID(fmt.Sprintf("99000000-0000-4000-8000-%012d", len(secrets)+1))
		secret.ResourceVersion = "1"
		secrets[secret.Name] = &secret
		creates = append(creates, secret.Name)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(secret)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	// Only the transport endpoint and its real current CA replace chart data.
	plan.Kubernetes.Endpoint = server.URL
	plan.Kubernetes.RootsPEM = ca
	directory := t.TempDir()
	writePlan := func() {
		t.Helper()
		raw, e := json.Marshal(plan)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(directory, "preparation.json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writePlan()
	if e = os.WriteFile(filepath.Join(directory, "administrator-token"), []byte("synthetic-preparation-token"), 0600); e != nil {
		t.Fatal(e)
	}
	files, e := os.OpenRoot(directory)
	if e != nil {
		t.Fatal(e)
	}
	defer files.Close()
	if e = runSmallServicesPreparation(t.Context(), files); e != nil {
		mu.Lock()
		d := slices.Clone(denials)
		mu.Unlock()
		t.Fatalf("fresh rendered hook: %v; denied=%v", e, d)
	}
	mu.Lock()
	order := slices.Clone(creates)
	original := map[string]*core.Secret{}
	for name, v := range secrets {
		original[name] = v.DeepCopy()
	}
	mu.Unlock()
	defer func() {
		for _, v := range original {
			for _, b := range v.Data {
				clear(b)
			}
		}
	}()
	expectedOrder := []string{"trial-keycloak-state", "trial-postgres-state", "trial-objectstore-state", "trial-objectstore-iam"}
	if bundledKeys {
		expectedOrder = append(expectedOrder, "trial-openbao-state")
	}
	if !slices.Equal(order, expectedOrder) {
		t.Fatalf("actual preparation order=%v", order)
	}
	if e = runSmallServicesPreparation(t.Context(), files); e != nil {
		mu.Lock()
		d := slices.Clone(denials)
		mu.Unlock()
		t.Fatalf("retained rendered hook: %v; denied=%v", e, d)
	}
	assertUnchanged := func() {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(creates) != len(expectedOrder) || len(secrets) != len(original) {
			t.Fatal("repeat/changed target created new private state")
		}
		for name, before := range original {
			now := secrets[name]
			if now == nil || now.UID != before.UID || now.ResourceVersion != before.ResourceVersion || len(now.Data) != len(before.Data) {
				t.Fatal("retained private identity changed")
			}
			for key, raw := range before.Data {
				if !bytes.Equal(raw, now.Data[key]) {
					t.Fatal("retained private bytes changed")
				}
			}
		}
	}
	assertUnchanged()
	// A legitimate external DB selection is structurally valid, but cannot
	// replace the target already bound into retained Keycloak material. No SQL
	// credential/CA files are present, and only the exact KC state GET may occur.
	plan.Keycloak.Database.Host = "changed-postgres.example"
	plan.KeycloakExternalDatabase = true
	writePlan()
	mu.Lock()
	requestCount := len(requests)
	mu.Unlock()
	if e = runSmallServicesPreparation(t.Context(), files); e == nil {
		t.Fatal("changed retained Keycloak DB target accepted")
	}
	assertUnchanged()
	mu.Lock()
	after := slices.Clone(requests[requestCount:])
	mu.Unlock()
	if !slices.Equal(after, []string{"get secrets/trial-keycloak-state"}) {
		t.Fatalf("changed target reached later preparation or SQL prerequisites: %v", after)
	}
}
