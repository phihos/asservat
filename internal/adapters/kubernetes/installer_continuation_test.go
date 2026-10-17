package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// ADR-183: the empty audit Secrets are allocated once; a rerun accepts only a
// still-empty existing Secret, never one already holding material.
func TestProviderAuditSecretsAreEmptyAndNeverAdopted(t *testing.T) {
	for _, mode := range []string{"create", "rerun-empty", "rerun-material"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/hub/secrets/")
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && mode == "create":
					var s core.Secret
					_ = json.NewDecoder(r.Body).Decode(&s)
					if len(s.Data) != 0 {
						t.Error("allocated a Secret with material")
					}
					s.UID = "10000000-0000-4000-8000-000000000001"
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(s)
				case r.Method == http.MethodPost:
					w.WriteHeader(409)
					_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
				case r.Method == http.MethodGet:
					s := core.Secret{TypeMeta: meta.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: meta.ObjectMeta{Name: name, UID: "10000000-0000-4000-8000-000000000002"}, Type: core.SecretTypeOpaque}
					if mode == "rerun-material" {
						s.Data = map[string][]byte{"credentials.json": []byte("{}")}
					}
					_ = json.NewEncoder(w).Encode(s)
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			worker, owner, err := EnsureProviderAuditSecrets(context.Background(), config, "hub", ownerID(1))
			if mode == "rerun-material" {
				if err == nil {
					t.Fatal("adopted a Secret holding material")
				}
				return
			}
			if err != nil || worker.Name != runtimeResourceNames(ownerID(1)).WorkerProviders || owner.Name != contracts.OwnerProviderAuditSecretName(ownerID(1)) || worker.UID == "" {
				t.Fatal("provider audit Secrets", err, worker, owner)
			}
		})
	}
}

// The outbox never regresses to an earlier phase's recipe.
func TestInstallerRecipeOutboxOnlyAdvances(t *testing.T) {
	var stored string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			if stored != "" {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
				return
			}
			fallthrough
		case http.MethodPut:
			var c core.ConfigMap
			_ = json.NewDecoder(r.Body).Decode(&c)
			stored = c.Data["outbox.json"]
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(c)
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(core.ConfigMap{TypeMeta: meta.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: meta.ObjectMeta{Name: contracts.InstallerRecipeOutboxName(ownerID(1))}, Data: map[string]string{"outbox.json": stored}})
		}
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	publish := func(phase int) error {
		return PublishInstallerRecipe(context.Background(), config, "hub", ownerID(1), contracts.InstallerRecipeOutbox{Format: contracts.InstallerRecipeOutboxFormat, Phase: phase, Purpose: "worker-provider", Recipe: json.RawMessage(`{"roles":[]}`)})
	}
	if err := publish(3); err != nil {
		t.Fatal(err)
	}
	if err := publish(1); err == nil {
		t.Fatal("outbox regressed to an earlier phase")
	}
	if err := publish(4); err != nil || !strings.Contains(stored, `"phase":4`) {
		t.Fatal("later phase refused", err)
	}
}

// The audit credential fills only the original empty Secret; a rerun accepts
// the exact same content and nothing else. The inbox answers one phase.
func TestInstallerAuditFillAndInboxPhase(t *testing.T) {
	uid := "10000000-0000-4000-8000-000000000003"
	var data map[string][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := core.Secret{TypeMeta: meta.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: meta.ObjectMeta{Name: strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/hub/secrets/"), UID: types.UID(uid), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: data}
		if r.Method == http.MethodPut {
			_ = json.NewDecoder(r.Body).Decode(&s)
			data = s.Data
		}
		_ = json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	ref := contracts.WorkerObjectReference{Name: "audit", UID: uid}
	fill := func(b string) error {
		return FillProviderAuditSecret(context.Background(), config, "hub", ref, "a.json", []byte(b))
	}
	if err := fill("one"); err != nil || string(data["a.json"]) != "one" {
		t.Fatal("empty fill", err)
	}
	if err := fill("one"); err != nil {
		t.Fatal("exact replay refused", err)
	}
	if err := fill("two"); err == nil {
		t.Fatal("replaced existing material")
	}
	data = map[string][]byte{contracts.InstallerInboxPhase: []byte("1"), contracts.InstallerInboxInspectionToken: []byte("t"), contracts.InstallerInboxAuditCredential: []byte("{}")}
	if _, err := ReadInstallerInbox(context.Background(), config, "hub", ownerID(1), 3); err == nil {
		t.Fatal("inbox answered another phase")
	}
	if got, err := ReadInstallerInbox(context.Background(), config, "hub", ownerID(1), 1); err != nil || got.UID != uid {
		t.Fatal("inbox", err)
	}
}

// ADR-188: the settle wait returns only after the controller's delayed status
// write, once the resource version stops changing.
func TestAwaitDeploymentsSettledWaitsForControllerStatus(t *testing.T) {
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reads.Add(1)
		d := apps.Deployment{TypeMeta: meta.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}, ObjectMeta: meta.ObjectMeta{Name: "worker", Generation: 1, ResourceVersion: "10"}}
		if n >= 3 {
			// The released controller writes its status on the third read.
			d.ResourceVersion = "11"
			d.Status = apps.DeploymentStatus{ObservedGeneration: 1, Conditions: []apps.DeploymentCondition{{Type: apps.DeploymentProgressing, Status: core.ConditionTrue, Reason: "NewReplicaSetAvailable"}}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := AwaitDeploymentsSettled(ctx, config, "hub", "worker"); err != nil || reads.Load() != 4 {
		t.Fatal("settled", err, reads.Load())
	}
}

// ADR-194 decision 11: the inbox carries exactly the three public files, and
// the operator public Secret is created once; a rerun accepts only the same
// content.
func TestOwnerPublicSecretAndInboxPublicFiles(t *testing.T) {
	var stored *core.Secret
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			if stored != nil {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: meta.StatusReasonAlreadyExists, Code: 409})
				return
			}
			stored = &core.Secret{}
			_ = json.NewDecoder(r.Body).Decode(stored)
			stored.TypeMeta, stored.UID = meta.TypeMeta{Kind: "Secret", APIVersion: "v1"}, types.UID(ownerID(7))
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	files := map[string][]byte{contracts.OwnerPublicClientSecretFile: []byte("synthetic-client"), contracts.OwnerPublicTLSCertificate: []byte("synthetic-crt"), contracts.OwnerPublicTLSKey: []byte("synthetic-key")}
	if err := WriteOwnerPublicSecret(context.Background(), config, "hub", ownerID(1), files); err != nil || stored.Name != contracts.OwnerPublicProjectionName(ownerID(1)) || stored.Immutable != nil || len(stored.Data) != 3 {
		t.Fatal("public secret", err)
	}
	if err := WriteOwnerPublicSecret(context.Background(), config, "hub", ownerID(1), files); err != nil {
		t.Fatal("exact rerun refused", err)
	}
	files[contracts.OwnerPublicTLSKey] = []byte("other-key")
	if err := WriteOwnerPublicSecret(context.Background(), config, "hub", ownerID(1), files); err == nil {
		t.Fatal("replaced the operator's public material")
	}
	delete(files, contracts.OwnerPublicTLSKey)
	if err := WriteOwnerPublicSecret(context.Background(), config, "hub", ownerID(2), files); err == nil {
		t.Fatal("incomplete public material accepted")
	}
	stored = &core.Secret{TypeMeta: meta.TypeMeta{Kind: "Secret", APIVersion: "v1"}, ObjectMeta: meta.ObjectMeta{UID: types.UID(ownerID(8))}, Type: core.SecretTypeOpaque,
		Data: map[string][]byte{contracts.InstallerInboxPhase: []byte("3"), contracts.InstallerInboxInspectionToken: []byte("t"), contracts.InstallerInboxAuditCredential: []byte("{}"), contracts.OwnerPublicClientSecretFile: []byte("c"), contracts.OwnerPublicTLSCertificate: []byte("crt"), contracts.OwnerPublicTLSKey: []byte("key"), "unrelated": []byte("x")}}
	got, err := ReadInstallerInbox(context.Background(), config, "hub", ownerID(1), 3)
	if err != nil || len(got.Public) != 3 || string(got.Public[contracts.OwnerPublicTLSKey]) != "key" {
		t.Fatal("inbox public files", err, got.Public)
	}
}
