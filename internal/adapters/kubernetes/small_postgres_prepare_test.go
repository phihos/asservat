package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func smallPostgresTestPlan() contracts.SmallPostgresPlan {
	return contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: "hub", Name: "trial"}
}

func TestSmallPostgresPrepareCreateReplayAndUnknownReadback(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "unknown"}[unknown], func(t *testing.T) {
			p := smallPostgresTestPlan()
			var retained *core.Secret
			creates, gets, pvcGets, workloadGets := 0, 0, 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(r.URL.Path, "/persistentvolumeclaims/") {
					pvcGets++
					http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
					return
				}
				if strings.Contains(r.URL.Path, "/statefulsets/") || strings.Contains(r.URL.Path, "/pods/") {
					workloadGets++
					http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
					return
				}
				if r.Method == http.MethodGet {
					gets++
					if retained == nil {
						http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
						return
					}
					_ = json.NewEncoder(w).Encode(retained)
					return
				}
				if r.Method != http.MethodPost {
					t.Errorf("unexpected mutation %s", r.Method)
					w.WriteHeader(500)
					return
				}
				creates++
				var v core.Secret
				if json.NewDecoder(r.Body).Decode(&v) != nil {
					t.Error("invalid create")
				}
				v.UID = types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
				v.ResourceVersion = "1"
				retained = &v
				if unknown {
					http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"InternalError","code":500}`, 500)
					return
				}
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			s, err := NewSmallPostgresPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, p)
			if err != nil {
				t.Fatal(err)
			}
			first, err := s.Prepare(t.Context())
			if err != nil || first.UID == "" {
				t.Fatal("create/readback failed", err)
			}
			second, err := s.Prepare(t.Context())
			if err != nil || second != first {
				t.Fatal("replay changed identity", err)
			}
			if creates != 1 || pvcGets != 0 || workloadGets != 0 || gets != 2+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatalf("unexpected requests create=%d pvc=%d workload=%d get=%d", creates, pvcGets, workloadGets, gets)
			}
		})
	}
}

func TestSmallPostgresPrepareStopsOnCancellation(t *testing.T) {
	p := smallPostgresTestPlan()
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, err := NewSmallPostgresPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = s.Prepare(ctx); err == nil || requests != 0 {
		t.Fatal("cancelled preparation reached the API")
	}
}
