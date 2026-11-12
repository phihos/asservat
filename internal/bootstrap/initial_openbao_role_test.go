package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
)

type initialBaoRenderedRoles struct {
	base           *rbac.ClusterRole
	added          *rbac.Role
	binding        *rbac.RoleBinding
	clusterBinding *rbac.ClusterRoleBinding
}

func renderInitialBaoRoles(t *testing.T, selected bool) initialBaoRenderedRoles {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("Helm is required")
	}
	provider := "external"
	if selected {
		provider = "openbao"
	}
	values := map[string]any{"bootstrap": smallServicesHelmBootstrap(), "services": map[string]any{"keyService": map[string]any{"provider": provider}}}
	raw, _ := json.Marshal(values)
	path := filepath.Join(t.TempDir(), "values.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, end := context.WithTimeout(t.Context(), 15*time.Second)
	defer end()
	rendered, err := exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "bootstrap", "--kube-version", "1.35.0", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("actual chart render: %v\n%s", err, rendered)
	}
	var result initialBaoRenderedRoles
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	for {
		var document json.RawMessage
		err = decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var header struct {
			Kind     string
			Metadata struct{ Name string }
		}
		if json.Unmarshal(document, &header) != nil {
			t.Fatal("chart document")
		}
		switch {
		case header.Kind == "ClusterRole" && header.Metadata.Name == "bootstrap-trial-bootstrap-runner":
			result.base = &rbac.ClusterRole{}
			err = json.Unmarshal(document, result.base)
		case header.Kind == "ClusterRoleBinding" && header.Metadata.Name == "bootstrap-trial-bootstrap-runner":
			result.clusterBinding = &rbac.ClusterRoleBinding{}
			err = json.Unmarshal(document, result.clusterBinding)
		case header.Kind == "Role" && header.Metadata.Name == "trial-openbao-bootstrap":
			result.added = &rbac.Role{}
			err = json.Unmarshal(document, result.added)
		case header.Kind == "RoleBinding" && header.Metadata.Name == "trial-openbao-bootstrap":
			result.binding = &rbac.RoleBinding{}
			err = json.Unmarshal(document, result.binding)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if result.base == nil || result.clusterBinding == nil || result.clusterBinding.RoleRef.APIGroup != rbac.GroupName || result.clusterBinding.RoleRef.Kind != "ClusterRole" || result.clusterBinding.RoleRef.Name != result.base.Name || !reflect.DeepEqual(result.clusterBinding.Subjects, []rbac.Subject{{Kind: "ServiceAccount", Namespace: "bootstrap", Name: "trial-bootstrap-runner"}}) {
		t.Fatal("original runner grant not bound to actual chart account")
	}
	return result
}
func initialBaoRuleAllows(rules []rbac.PolicyRule, resource, name, verb string) bool {
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, "") && slices.Contains(rule.Resources, resource) && slices.Contains(rule.Verbs, verb) && (len(rule.ResourceNames) == 0 || slices.Contains(rule.ResourceNames, name)) {
			return true
		}
	}
	return false
}

// Use the actual source/login/marker/identity/Ready helper. The fake API applies
// the real chart's bound rule union, including Kubernetes method/resource/name
// and namespace matching. It never fabricates a missing native privilege.
func TestInitialOpenBaoProviderUsesRenderedRunnerReadyRole(t *testing.T) {
	rendered := renderInitialBaoRoles(t, true)
	for _, mode := range []string{"actual-role", "without-role", "without-pvc", "without-patch"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialBaoProviderFixture(t, "")
			rules := slices.Clone(rendered.base.Rules)
			var localRules []rbac.PolicyRule
			if rendered.added != nil && rendered.binding != nil && mode != "without-role" {
				if rendered.added.Namespace != "bootstrap" || rendered.binding.Namespace != "bootstrap" || rendered.binding.RoleRef.APIGroup != rbac.GroupName || rendered.binding.RoleRef.Kind != "Role" || rendered.binding.RoleRef.Name != rendered.added.Name || !reflect.DeepEqual(rendered.binding.Subjects, []rbac.Subject{{Kind: "ServiceAccount", Namespace: "bootstrap", Name: "trial-bootstrap-runner"}}) {
					t.Fatal("selected Ready Role not bound to actual runner")
				}
				for _, rule := range rendered.added.Rules {
					if mode == "without-pvc" && slices.Contains(rule.Resources, "persistentvolumeclaims") || mode == "without-patch" && slices.Contains(rule.Resources, "secrets") {
						continue
					}
					localRules = append(localRules, rule)
				}
			}
			var mu sync.Mutex
			var denied []string
			cert, ca := smallServicesHookTLS(t)
			server := httptest.NewUnstartedServer(initialBaoBuffered(func(w http.ResponseWriter, r *http.Request) {
				parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
				resource, name, namespace := "", "", ""
				if len(parts) == 4 && parts[2] == "namespaces" {
					resource, name = "namespaces", parts[3]
				} else if len(parts) >= 6 && parts[2] == "namespaces" {
					namespace, resource, name = parts[3], parts[4], parts[5]
				}
				verb := map[string]string{http.MethodGet: "get", http.MethodPatch: "patch"}[r.Method]
				allowed := initialBaoRuleAllows(rules, resource, name, verb) || namespace == "bootstrap" && initialBaoRuleAllows(localRules, resource, name, verb)
				if !allowed {
					mu.Lock()
					denied = append(denied, verb+" "+resource+"/"+name)
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","reason":"Forbidden","code":403}`))
					return
				}
				f.native(w, r)
			}, nil))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			server.StartTLS()
			t.Cleanup(server.Close)
			// Only the test API origin changes. The provider keeps the real fixed
			// hostname/TLS check, and all three public source files remain consumed.
			f.config = rest.CopyConfig(f.config)
			f.config.Host = server.URL
			f.config.CAData = []byte(ca)
			block, _ := pem.Decode([]byte(ca))
			f.plan.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{block.Bytes}}
			source, _ := json.Marshal(f.plan)
			if err := os.WriteFile(filepath.Join(f.files.Name(), contracts.InitialBootstrapKeyServicePlanFile), source, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			provider, err := f.open(ctx)
			if provider != nil {
				defer provider.Close()
			}
			mu.Lock()
			d := slices.Clone(denied)
			mu.Unlock()
			if mode == "actual-role" {
				if err != nil || len(d) != 0 {
					t.Fatalf("actual rendered runner cannot acknowledge Ready: error=%v denied=%v", err, d)
				}
				f.mu.Lock()
				patches, private := f.patches, f.privateGets
				f.mu.Unlock()
				if patches != 1 || private != 0 {
					t.Fatal("Ready helper did not use one metadata-only patch")
				}
			} else {
				if err == nil || len(d) != 1 {
					t.Fatalf("omitted native rule did not refuse exactly: error=%v denied=%v", err, d)
				}
				wanted := "get persistentvolumeclaims/trial-openbao-data"
				if mode == "without-patch" {
					wanted = "patch secrets/trial-openbao-state"
				}
				if d[0] != wanted {
					t.Fatalf("omitted rule refused at wrong boundary: got=%s want=%s", d[0], wanted)
				}
			}
		})
	}
	if rendered.added == nil || rendered.binding == nil {
		t.Fatal("selected named Ready Role/Binding absent")
	}
	want := []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, ResourceNames: []string{"trial-openbao-data"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"trial-openbao-state"}, Verbs: []string{"patch"}}}
	if !reflect.DeepEqual(rendered.added.Rules, want) {
		t.Fatal("Ready additions exceed exact named PVC read and state metadata patch")
	}
}
func TestInitialOpenBaoReadyRoleAbsentForExternalProvider(t *testing.T) {
	rendered := renderInitialBaoRoles(t, false)
	if rendered.added != nil || rendered.binding != nil {
		t.Fatal("external selection added bundled-provider privileges")
	}
}
