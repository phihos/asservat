package kubernetes

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestSmallSeaweedResolutionDoesNotAdoptAReplacementAtEffectTime(t *testing.T) {
	p := smallSeaweedTestPlan()
	st := apps.StatefulSet{ObjectMeta: meta.ObjectMeta{Name: p.ServiceName(), Namespace: p.Namespace, UID: types.UID(swID("3"))}}
	pod := core.Pod{ObjectMeta: meta.ObjectMeta{Name: p.ServiceName() + "-0", Namespace: p.Namespace, UID: types.UID(swID("4"))}}
	reads, effects := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			effects++
			http.Error(w, "unexpected effect", 403)
			return
		}
		reads++
		if strings.Contains(r.URL.Path, "/statefulsets/") {
			_ = json.NewEncoder(w).Encode(st)
			return
		}
		if strings.Contains(r.URL.Path, "/pods/") {
			_ = json.NewEncoder(w).Encode(pod)
			return
		}
		t.Error("unexpected source lookup")
		http.NotFound(w, r)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	provider, err := ResolveSmallSeaweedProvider(t.Context(), config, p, swID("1"), contracts.WorkerObjectReference{Name: p.IAMSecretName(), UID: swID("5")})
	if err != nil || reads != 2 || provider.target.Pod.UID != string(pod.UID) || provider.target.StatefulSet.UID != string(st.UID) {
		t.Fatal("current identities not observed", err)
	}
	pod.UID = types.UID(swID("6"))
	if err := provider.Reload(t.Context(), []byte(`{}`)); err == nil || effects != 0 {
		t.Fatal("locator authorized a replacement or an effect", err)
	}
}
