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
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

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
