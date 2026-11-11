package kubernetes

import (
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
)

func smallPostgresTestPlan() contracts.SmallPostgresPlan {
	return contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: "hub", Name: "trial"}
}

func TestSmallPostgresMaterialBindsCredentialsTLSAndSelection(t *testing.T) {
	p := smallPostgresTestPlan()
	p.Keycloak = true
	now := time.Now().UTC()
	d, err := BuildSmallPostgresMaterial(p, now)
	if err != nil {
		t.Fatal(err)
	}
	defer smallPostgresClear(d)
	if p.MaxConnections() != 122 || ValidateSmallPostgresMaterial(p, d, now) != nil {
		t.Fatal("valid selected material refused")
	}
	for _, tc := range []struct {
		name   string
		change func(map[string][]byte)
	}{
		{"credential mismatch", func(m map[string][]byte) { m["ddl-verifier"] = m["administrator-verifier"] }},
		{"unknown key", func(m map[string][]byte) { m["extra"] = []byte("refuse") }},
		{"extra PEM", func(m map[string][]byte) { m["ca.crt"] = append(append([]byte{}, m["ca.crt"]...), m["ca.crt"]...) }},
		{"wrong private key", func(m map[string][]byte) { m["server.key"] = m["ca.key"] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := map[string][]byte{}
			for k, v := range d {
				copy[k] = v
			}
			tc.change(copy)
			if ValidateSmallPostgresMaterial(p, copy, now) == nil {
				t.Fatal("accepted changed material")
			}
		})
	}
	p.Keycloak = false
	if p.MaxConnections() != 117 || ValidateSmallPostgresMaterial(p, d, now) == nil {
		t.Fatal("accepted different declared topology")
	}
	p.Keycloak = true
	p.Namespace = "different"
	if ValidateSmallPostgresMaterial(p, d, now) == nil {
		t.Fatal("accepted different database identity")
	}
	p.Namespace = "hub"
	if ValidateSmallPostgresMaterial(p, d, now.AddDate(2, 0, 0)) == nil {
		t.Fatal("expired leaf accepted")
	}
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
			if creates != 1 || pvcGets != 3 || workloadGets != 2 || gets != 2+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatalf("unexpected requests create=%d pvc=%d workload=%d get=%d", creates, pvcGets, workloadGets, gets)
			}
		})
	}
}

func TestSmallPostgresPrepareRefusesRetainedPVCAndCancellation(t *testing.T) {
	p := smallPostgresTestPlan()
	creates := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			creates++
			w.WriteHeader(500)
			return
		}
		if strings.Contains(r.URL.Path, "/persistentvolumeclaims/") {
			_ = json.NewEncoder(w).Encode(core.PersistentVolumeClaim{ObjectMeta: meta.ObjectMeta{Name: p.DataPVCName()}})
			return
		}
		http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
	}))
	defer server.Close()
	s, err := NewSmallPostgresPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prepare(t.Context()); err == nil {
		t.Fatal("regenerated credentials over retained PVC")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = s.Prepare(ctx); err == nil || creates != 0 {
		t.Fatal("cancelled preparation mutated state")
	}
}

func TestSmallPostgresRetainedWorkloadCannotRecreateMissingDataPVC(t *testing.T) {
	for _, mode := range []string{"first-retry", "retained-pvc", "statefulset", "pod", "keycloak", "unavailable", "external-keycloak-ignored"} {
		t.Run(mode, func(t *testing.T) {
			p := smallPostgresTestPlan()
			p.Keycloak = mode == "keycloak"
			material, err := BuildSmallPostgresMaterial(p, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer smallPostgresClear(material)
			immutable := true
			state := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: p.StateSecretName(), Namespace: p.Namespace, UID: types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), ResourceVersion: "1", Labels: map[string]string{"asservat.io/private-role": "small-postgres"}}, Type: core.SecretTypeOpaque, Immutable: &immutable, Data: material}
			mutations, deployReads := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					mutations++
					w.WriteHeader(500)
					return
				}
				if strings.Contains(r.URL.Path, "/secrets/") {
					_ = json.NewEncoder(w).Encode(state)
					return
				}
				if strings.Contains(r.URL.Path, "/deployments/") {
					deployReads++
				}
				present := mode == "retained-pvc" && strings.Contains(r.URL.Path, "/persistentvolumeclaims/") || mode == "statefulset" && strings.Contains(r.URL.Path, "/statefulsets/") || mode == "pod" && strings.Contains(r.URL.Path, "/pods/") || (mode == "keycloak" || mode == "external-keycloak-ignored") && strings.Contains(r.URL.Path, "/deployments/")
				if present {
					_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Success"}`))
					return
				}
				if mode == "unavailable" && strings.Contains(r.URL.Path, "/statefulsets/") {
					http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"ServiceUnavailable","code":503}`, 503)
					return
				}
				http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
			}))
			defer server.Close()
			s, err := NewSmallPostgresPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Prepare(t.Context())
			wantErr := mode == "statefulset" || mode == "pod" || mode == "keycloak" || mode == "unavailable"
			if (err != nil) != wantErr {
				t.Fatalf("retained workload / data-loss refusal=%t; want %t", err != nil, wantErr)
			}
			if mutations != 0 {
				t.Fatal("replay issued mutation")
			}
			if !p.Keycloak && deployReads != 0 {
				t.Fatal("external identity probed as bundled database")
			}
		})
	}
}
