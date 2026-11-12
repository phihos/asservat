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

func TestInitialBootstrapRunnerHelmPostgresProjectionParity(t *testing.T) {
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
				values := map[string]any{"bootstrap": b}
				if continuation {
					b["continuation"] = map[string]any{"enabled": true, "workerProvider": map[string]string{"authMount": "worker-k8s", "authMountAccessor": "worker-accessor"}, "ownerProvider": map[string]string{"authMount": "owner-k8s", "authMountAccessor": "owner-accessor"}, "ownerIssuerRootsPEM": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"}
				}
				if bundled {
					values["services"] = map[string]any{"postgres": map[string]any{"provider": "bundled", "bundled": map[string]string{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}}}
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
				if bundled && (input.Postgres.Host != "install-postgres.trusted-bootstrap.svc" || input.Postgres.RootsSource != contracts.InitialBootstrapBundledPostgresRoots || input.Postgres.RootsPEM != "" || input.Postgres.MaxConnections != 2 || refs.PostgresSecret != "install-postgres-state") {
					t.Fatal("bundled input lost exact endpoint/root/client-pool split")
				}
				if !bundled && (input.Postgres.RootsSource != "" || refs.PostgresSecret != "" || input.Postgres.Host != "external.example") {
					t.Fatal("external wire changed")
				}
				sum := sha256.Sum256([]byte(cm.Data["bootstrap.json"] + "\n" + cm.Data["runner.json"]))
				plan := InitialBootstrapRunnerPlan{Namespace: input.BootstrapNamespace, Name: input.Name, Image: input.Image, InputDigest: hex.EncodeToString(sum[:]), ProducerSecret: refs.ProducerSecret, SchemaSecret: refs.SchemaSecret, RetirementSecret: refs.RetirementSecret, RegistrySecret: refs.RegistrySecret, ProbeAudience: input.ProbeAudience, ContinuationDigest: refs.ContinuationDigest, PostgresSecret: refs.PostgresSecret}
				want, err := BuildInitialBootstrapRunner(plan)
				if err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(pod)
				expected, _ := json.Marshal(want)
				if !bytes.Equal(a, expected) {
					t.Fatalf("Helm/Go runner differs\nHelm:%s\nGo:%s", a, expected)
				}
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

func TestInitialBootstrapRunnerBundledResumeRejectsAmbiguousSource(t *testing.T) {
	for _, mode := range []string{"terminal", "missing-ref", "wrong-ref", "missing-source", "mixed-pem", "wrong-endpoint", "server-cap-as-pool"} {
		t.Run(mode, func(t *testing.T) {
			plan, cm, pod := initialBootstrapRunnerFixture(t)
			input, _ := contracts.DecodeInitialBootstrapInput(strings.NewReader(cm.Data["bootstrap.json"]))
			refs, _ := contracts.DecodeInitialBootstrapRunnerInput(strings.NewReader(cm.Data["runner.json"]))
			input.Postgres = contracts.InitialBootstrapPostgresInput{Host: plan.Name + "-postgres." + plan.Namespace + ".svc", Port: 5432, Database: "asservat", MaxConnections: 2, RootsSource: contracts.InitialBootstrapBundledPostgresRoots}
			refs.PostgresSecret = plan.Name + "-postgres-state"
			switch mode {
			case "missing-ref":
				refs.PostgresSecret = ""
			case "wrong-ref":
				refs.PostgresSecret = "foreign"
			case "missing-source":
				input.Postgres.RootsSource = ""
			case "mixed-pem":
				input.Postgres.RootsPEM = "PUBLIC-CA"
			case "wrong-endpoint":
				input.Postgres.Host = "other"
			case "server-cap-as-pool":
				input.Postgres.MaxConnections = 117
			}
			a, _ := json.Marshal(input)
			b, _ := json.Marshal(refs)
			sum := sha256.Sum256([]byte(string(a) + "\n" + string(b)))
			plan.InputDigest = hex.EncodeToString(sum[:])
			plan.PostgresSecret = plan.Name + "-postgres-state"
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
				t.Fatal("orchestration resume read private PostgreSQL state")
			}
		})
	}
}
