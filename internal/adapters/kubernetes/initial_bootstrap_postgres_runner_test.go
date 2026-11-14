package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

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
