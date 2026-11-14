package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func smallSeaweedTestPlan() contracts.SmallSeaweedPlan {
	return contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: "hub", Name: "trial", Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64)}
}

type smallSeaweedFixture struct {
	plan     contracts.SmallSeaweedPlan
	secrets  map[string]*core.Secret
	retained string
	unknown  string
	corrupt  bool
	creates  []string
	reads    int
}

func (f *smallSeaweedFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	absent := func() { http.Error(w, `{"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404}`, 404) }
	if r.Method == http.MethodGet {
		f.reads++
		for name, secret := range f.secrets {
			if strings.HasSuffix(r.URL.Path, "/secrets/"+name) {
				_ = json.NewEncoder(w).Encode(secret)
				return
			}
		}
		backend := ""
		switch {
		case strings.Contains(r.URL.Path, "/persistentvolumeclaims/"):
			backend = "pvc"
		case strings.Contains(r.URL.Path, "/statefulsets/"):
			backend = "statefulset"
		case strings.Contains(r.URL.Path, "/pods/"):
			backend = "pod"
		}
		if backend != "" && backend == f.retained {
			_, _ = w.Write([]byte(`{"metadata":{"name":"retained"}}`))
			return
		}
		absent()
		return
	}
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/secrets") {
		panic("unexpected mutable request")
	}
	var secret core.Secret
	if json.NewDecoder(r.Body).Decode(&secret) != nil {
		panic("secret input")
	}
	f.creates = append(f.creates, secret.Name)
	secret.UID = types.UID(swID("6"))
	if secret.Name == f.plan.IAMSecretName() {
		secret.UID = types.UID(swID("7"))
	}
	secret.ResourceVersion = "1"
	if f.corrupt {
		secret.Data["tls.key"] = secret.Data["ca.key"]
	}
	f.secrets[secret.Name] = &secret
	if f.unknown == secret.Name {
		http.Error(w, `{"apiVersion":"v1","kind":"Status","reason":"InternalError","code":500}`, 500)
		return
	}
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(secret)
}
func newSmallSeaweedFixture(t *testing.T) (*SmallSeaweedPreparation, *smallSeaweedFixture) {
	t.Helper()
	f := &smallSeaweedFixture{plan: smallSeaweedTestPlan(), secrets: map[string]*core.Secret{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	p, e := NewSmallSeaweedPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, f.plan)
	if e != nil {
		t.Fatal(e)
	}
	return p, f
}
func seedSmallSeaweedState(t *testing.T, f *smallSeaweedFixture) {
	t.Helper()
	data, e := BuildSmallSeaweedMaterial(f.plan, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	f.secrets[f.plan.StateSecretName()] = &core.Secret{ObjectMeta: meta.ObjectMeta{Name: f.plan.StateSecretName(), Namespace: f.plan.Namespace, UID: types.UID(swID("6")), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "small-seaweed"}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}
	t.Cleanup(func() { clearSmallSeaweedData(data) })
}
func TestSmallSeaweedPrepareCreateReplayAndUnknownReadback(t *testing.T) {
	for _, which := range []string{"", "state"} {
		t.Run(which, func(t *testing.T) {
			p, f := newSmallSeaweedFixture(t)
			if which == "state" {
				f.unknown = f.plan.StateSecretName()
			}
			first, e := p.Prepare(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer clear(first.RootsPEM)
			original := f.secrets[f.plan.StateSecretName()].DeepCopy()
			defer clearSmallSeaweedData(original.Data)
			second, e := p.Prepare(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer clear(second.RootsPEM)
			if first.State != second.State || first.Admin != second.Admin || first.BackendID != second.BackendID || first.InitializationID != second.InitializationID || !bytes.Equal(first.RootsPEM, second.RootsPEM) || !sameSmallSeaweedData(original.Data, f.secrets[f.plan.StateSecretName()].Data) || len(f.creates) != 1 {
				t.Fatal("replay changed original backend")
			}
		})
	}
}
func TestSmallSeaweedPrepareRefusesChangedState(t *testing.T) {
	for _, mode := range []string{"changed", "unknown-mismatch", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p, f := newSmallSeaweedFixture(t)
			switch mode {
			case "changed":
				seedSmallSeaweedState(t, f)
				f.secrets[f.plan.StateSecretName()].Data[contracts.SmallSeaweedBackendKey] = []byte(swID("8"))
			case "unknown-mismatch":
				f.unknown = f.plan.StateSecretName()
				f.corrupt = true
			}
			ctx := t.Context()
			if mode == "cancelled" {
				var end context.CancelFunc
				ctx, end = context.WithCancel(ctx)
				end()
			}
			if _, e := p.Prepare(ctx); e == nil {
				t.Fatal("regenerated or accepted unknown retained state")
			}
			want := 0
			if mode == "unknown-mismatch" {
				want = 1
			}
			if len(f.creates) != want {
				t.Fatal("unexpected create after refusal")
			}
		})
	}
}
