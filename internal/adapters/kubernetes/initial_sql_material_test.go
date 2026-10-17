package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

type initialMaterialRoundTrip func(*http.Request) (*http.Response, error)

func (f initialMaterialRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestInitialSQLMaterialRequiresOriginalPrivatePinAndCurrentOperator(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "replacement", "mutable", "wrong-request", "repeated-password", "wrong-admin", "guard-lost", "expired-after-private-read"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparerFixture(t, "")
			p := f.preparer(t)
			if _, e := p.Declare(context.Background()); e != nil {
				t.Fatal(e)
			}
			password := func(b byte) string {
				return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{b}), 32)))
			}
			m := contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: f.plan.InstallationID, RequestID: f.plan.RequestID, PreparationPassword: password('a'), AuditPassword: password('b'), ActivationPassword: password('c')}
			if mode == "wrong-request" {
				m.RequestID = ownerID(80)
			}
			if mode == "repeated-password" {
				m.AuditPassword = m.PreparationPassword
			}
			payload, _ := json.Marshal(m)
			defer clear(payload)
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "initial-material", Namespace: f.plan.BootstrapNamespace.Name}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": payload}}
			if mode == "mutable" {
				secret.Immutable = ptr.To(false)
			}
			raw, _ := json.Marshal(secret)
			defer clear(raw)
			path := "/api/v1/namespaces/bootstrap/secrets/initial-material"
			f.mu.Lock()
			f.store(path, raw)
			uid := f.objects[path]["metadata"].(map[string]any)["uid"].(string)
			if mode == "missing" {
				delete(f.objects, path)
			}
			if mode == "replacement" {
				f.objects[path]["metadata"].(map[string]any)["uid"] = ownerID(90)
			}
			if mode == "wrong-admin" || mode == "guard-lost" {
				f.fault = mode
			}
			before := fmt.Sprint(f.posts)
			f.mu.Unlock()
			if mode == "expired-after-private-read" {
				f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
					return initialMaterialRoundTrip(func(r *http.Request) (*http.Response, error) {
						reply, e := next.RoundTrip(r)
						if r.URL.Path == path {
							f.mu.Lock()
							f.shift = 6 * time.Second
							f.mu.Unlock()
						}
						return reply, e
					})
				}
				p = f.preparer(t)
			}
			reader, e := NewInitialSQLMaterialReader(p, contracts.WorkerObjectReference{Name: "initial-material", UID: uid})
			if e != nil {
				t.Fatal(e)
			}
			got, until, e := reader.ReadInitialSQLMaterial(context.Background())
			if mode == "valid" {
				if e != nil || got != m || !time.Now().Before(until) {
					t.Fatal("retained material unavailable", e)
				}
			} else if e == nil || got.PreparationPassword != "" || !until.IsZero() {
				t.Fatal("unauthorized or replaced private material returned")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if before != fmt.Sprint(f.posts) {
				t.Fatal("read created or replaced private material")
			}
		})
	}
}
