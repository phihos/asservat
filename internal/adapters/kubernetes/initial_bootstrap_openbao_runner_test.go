package kubernetes

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

func TestInitialBootstrapRunnerHelmOpenBaoProjectionParity(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm unavailable")
	}
	for _, bundled := range []bool{false, true} {
		for _, continuation := range []bool{false, true} {
			name := "external"
			if bundled {
				name = "bundled"
			}
			if continuation {
				name += "-continue"
			}
			t.Run(name, func(t *testing.T) {
				b := map[string]any{"enabled": true, "name": "install", "targetNamespace": "runtime", "image": "registry.example/asservat@sha256:" + strings.Repeat("a", 64), "registrySecret": "original-pull", "probeAudience": "original-audience", "secrets": map[string]string{"producer": "provider-material", "schema": "sql-ddl", "retirement": "sql-retire"}, "postgres": map[string]any{"host": "external.example", "port": 5432, "database": "asservat", "maxConnections": 2, "rootsPEM": "PUBLIC-CA"}, "auditStore": map[string]string{"endpoint": "https://store.example", "region": "region-a", "bucket": "audit", "rootsPEM": "PUBLIC-CA"}, "keyService": map[string]string{"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"}, "fleet": map[string]any{"issuer": "https://id.example/realms/org", "clients": []string{"console"}, "subjects": []map[string]string{{"id": "operator", "kind": "human"}}}, "continuation": map[string]any{"enabled": continuation}}
				values := map[string]any{"bootstrap": b, "services": map[string]any{"keyService": map[string]string{"provider": "openbao"}}}
				if continuation {
					b["continuation"] = map[string]any{"enabled": true, "workerProvider": map[string]string{"authMount": "worker-k8s", "authMountAccessor": "worker-accessor"}, "ownerProvider": map[string]string{"authMount": "owner-k8s", "authMountAccessor": "owner-accessor"}, "ownerIssuerRootsPEM": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"}
				}
				if bundled {
					values["services"].(map[string]any)["postgres"] = map[string]any{"provider": "bundled", "bundled": map[string]string{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}}
				}
				v, _ := json.Marshal(values)
				path := filepath.Join(t.TempDir(), "values.json")
				if os.WriteFile(path, v, 0600) != nil {
					t.Fatal("values")
				}
				output, err := exec.CommandContext(t.Context(), "helm", "template", "trial", "../../../charts/asservat", "--namespace", "trusted-bootstrap", "-f", path, "--show-only", "templates/bootstrap-input.yaml", "--show-only", "templates/bootstrap-runner.yaml").CombinedOutput()
				if err != nil {
					t.Fatalf("helm failed: %s", output)
				}
				var cm core.ConfigMap
				var pod core.Pod
				r := kyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(output)))
				for {
					raw, err := r.Read()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					var kind struct{ Kind string }
					if yaml.Unmarshal(raw, &kind) != nil {
						t.Fatal("manifest")
					}
					switch kind.Kind {
					case "ConfigMap":
						if yaml.Unmarshal(raw, &cm) != nil {
							t.Fatal("input")
						}
					case "Pod":
						if yaml.Unmarshal(raw, &pod) != nil {
							t.Fatal("pod")
						}
					}
				}
				input, err := contracts.DecodeInitialBootstrapInput(strings.NewReader(cm.Data["bootstrap.json"]))
				if err != nil {
					t.Fatal(err)
				}
				refs, err := contracts.DecodeInitialBootstrapRunnerInput(strings.NewReader(cm.Data["runner.json"]))
				if err != nil {
					t.Fatal(err)
				}
				if refs.KeyServiceSecret != "install-openbao-state" || input.KeyService.RootsSource != contracts.InitialBootstrapBundledOpenBaoRoots || input.KeyService.RootsPEM != "" || input.KeyService.Endpoint != "https://install-openbao.trusted-bootstrap.svc:8200" || input.KeyService.AuditMount != contracts.SmallOpenBaoAuditMount {
					t.Fatal("bundled OpenBao lost exact source binding")
				}
				if bundled && (input.Postgres.Host != "install-postgres.trusted-bootstrap.svc" || input.Postgres.RootsSource != contracts.InitialBootstrapBundledPostgresRoots || input.Postgres.RootsPEM != "" || input.Postgres.MaxConnections != 2 || refs.PostgresSecret != "install-postgres-state") {
					t.Fatal("bundled input lost exact endpoint/root/client-pool split")
				}
				if !bundled && (input.Postgres.RootsSource != "" || refs.PostgresSecret != "" || input.Postgres.Host != "external.example") {
					t.Fatal("external wire changed")
				}
				sum := sha256.Sum256([]byte(cm.Data["bootstrap.json"] + "\n" + cm.Data["runner.json"]))
				plan := InitialBootstrapRunnerPlan{Namespace: input.BootstrapNamespace, Name: input.Name, Image: input.Image, InputDigest: hex.EncodeToString(sum[:]), ProducerSecret: refs.ProducerSecret, SchemaSecret: refs.SchemaSecret, RetirementSecret: refs.RetirementSecret, RegistrySecret: refs.RegistrySecret, ProbeAudience: input.ProbeAudience, ContinuationDigest: refs.ContinuationDigest, PostgresSecret: refs.PostgresSecret, KeyServiceSecret: refs.KeyServiceSecret}
				want, err := BuildInitialBootstrapRunner(plan)
				if err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(pod)
				expected, _ := json.Marshal(want)
				if !bytes.Equal(a, expected) {
					t.Fatalf("Helm/Go runner differs\nHelm:%s\nGo:%s", a, expected)
				}
				assertOpenBaoRunnerCompartments(t, want, continuation)
				for _, volume := range want.Spec.Volumes {
					if volume.Projected != nil {
						for _, source := range volume.Projected.Sources {
							if source.Secret != nil {
								if len(source.Secret.Items) == 0 {
									t.Fatal("whole Secret projected")
								}
								for _, item := range source.Secret.Items {
									if item.Key == "ca.key" || item.Key == "server.key" {
										t.Fatal("private CA/server key reached installer")
									}
								}
							}
						}
					}
				}
			})
		}
	}
}

func TestInitialBootstrapRunnerOpenBaoResumeRejectsAmbiguousSource(t *testing.T) {
	for _, mode := range []string{"terminal", "missing-ref", "wrong-ref", "missing-source", "mixed-pem", "wrong-endpoint", "wrong-mount"} {
		t.Run(mode, func(t *testing.T) {
			plan, cm, pod, _ := initialInstallerRunnerFixture(t, true)
			input, _ := contracts.DecodeInitialBootstrapInput(strings.NewReader(cm.Data["bootstrap.json"]))
			refs, _ := contracts.DecodeInitialBootstrapRunnerInput(strings.NewReader(cm.Data["runner.json"]))
			input.KeyService = contracts.InitialBootstrapKeyServiceInput{Endpoint: "https://" + plan.Name + "-openbao." + plan.Namespace + ".svc:8200", AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: "audit", RootsSource: contracts.InitialBootstrapBundledOpenBaoRoots}
			refs.KeyServiceSecret = plan.Name + "-openbao-state"
			switch mode {
			case "missing-ref":
				refs.KeyServiceSecret = ""
			case "wrong-ref":
				refs.KeyServiceSecret = "foreign"
			case "missing-source":
				input.KeyService.RootsSource = ""
			case "mixed-pem":
				input.KeyService.RootsPEM = "PUBLIC-CA"
			case "wrong-endpoint":
				input.KeyService.Endpoint = "other"
			case "wrong-mount":
				input.KeyService.AuditMount = "foreign"
			}
			a, _ := json.Marshal(input)
			b, _ := json.Marshal(refs)
			sum := sha256.Sum256([]byte(string(a) + "\n" + string(b)))
			plan.InputDigest = hex.EncodeToString(sum[:])
			plan.KeyServiceSecret = plan.Name + "-openbao-state"
			want, err := BuildInitialBootstrapRunner(plan)
			if err != nil {
				t.Fatal(err)
			}
			pod.Spec = want.Spec
			pod.Spec.NodeName = "node-original"
			pod.Annotations = want.Annotations
			cm.Name = initialBootstrapRunnerInputName(plan.Name, plan.InputDigest)
			cm.Data = map[string]string{"bootstrap.json": string(a), "runner.json": string(b)}
			deletes, secretReads := 0, 0
			removed := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/secrets/") {
					secretReads++
					http.Error(w, "unavailable", 403)
					return
				}
				if strings.Contains(r.URL.Path, "/configmaps/") {
					permissionReply(w, cm)
					return
				}
				if r.Method == http.MethodDelete {
					deletes++
					removed = true
					permissionReply(w, &meta.Status{Status: "Success"})
					return
				}
				if removed {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					permissionReply(w, &meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonNotFound, Code: 404})
					return
				}
				permissionReply(w, pod)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			_, err = ResumeInitialBootstrapRunner(t.Context(), &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, plan.Namespace, plan.Name)
			if mode == "terminal" {
				if err != nil || deletes != 1 {
					t.Fatal("terminal runner refused", err)
				}
			} else if err == nil || deletes != 0 {
				t.Fatal("ambiguous input allowed removal")
			}
			if secretReads != 0 {
				t.Fatal("orchestration resume read private OpenBao state")
			}
		})
	}
}

// The fixed public selection is available wherever desired input is resolved;
// only producer/continuation own the provider setup token. No whole state Secret
// (seal key, CA private key, root credential) enters any installer compartment.
func assertOpenBaoRunnerCompartments(t *testing.T, pod *core.Pod, continuation bool) {
	t.Helper()
	public, tokens := map[string]bool{}, map[string]bool{}
	for _, v := range pod.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, source := range v.Projected.Sources {
			if source.Secret != nil && source.Secret.Name == "install-openbao-state" {
				public[v.Name] = true
				expected := map[string]string{contracts.SmallOpenBaoPlanKey: contracts.InitialBootstrapKeyServicePlanFile, "ca.crt": contracts.InitialBootstrapKeyServiceCAFile, contracts.SmallOpenBaoBackendKey: contracts.InitialBootstrapKeyServiceBackendFile}
				if len(source.Secret.Items) != len(expected) || source.Secret.Optional == nil || *source.Secret.Optional {
					t.Fatal("OpenBao public projection broadened or optional")
				}
				for _, item := range source.Secret.Items {
					if expected[item.Key] != item.Path {
						t.Fatal("private/foreign OpenBao key projected")
					}
					delete(expected, item.Key)
				}
				if len(expected) != 0 {
					t.Fatal("missing OpenBao public input")
				}
			}
			if token := source.ServiceAccountToken; token != nil && token.Path == contracts.InitialBootstrapKeyServiceTokenFile {
				tokens[v.Name] = true
				if token.Audience != contracts.SmallOpenBaoSetupAudience || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 {
					t.Fatal("provider setup token scope changed")
				}
			}
		}
	}
	if !public["producer-input"] || !public["retirement-input"] || public["continuation-input"] != continuation || len(public) != 2+boolCount(continuation) || !tokens["producer-input"] || tokens["retirement-input"] || tokens["continuation-input"] != continuation || len(tokens) != 1+boolCount(continuation) {
		t.Fatal("provider public/token compartment mismatch")
	}
}
func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestInitialBootstrapRunnerOpenBaoRejectsForeignSecret(t *testing.T) {
	plan, _, _ := initialBootstrapRunnerFixture(t)
	plan.KeyServiceSecret = "foreign-openbao-state"
	if _, err := BuildInitialBootstrapRunner(plan); err == nil {
		t.Fatal("foreign bundled provider Secret accepted")
	}
}
