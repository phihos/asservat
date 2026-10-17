package kms

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-193: the federation's four provider purposes log in through Kubernetes
// auth only under the current proof, keep each credential on its own path,
// and seal/open audit keys with borrowed tokens.
func TestFederationProviderEffectsAreProofBoundAndPurposeSeparated(t *testing.T) {
	tlsFixture := newOwnerProviderControlFixture(t)
	installation := "10000000-0000-4000-8000-000000000001"
	in := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000000002", Concurrency: 2,
		KeyService: contracts.FederationKeyService{Endpoint: tlsFixture.server.URL, Roots: [][]byte{tlsFixture.server.Certificate().Raw}, AuditMount: "audit", AuditKey: "federation", PKIMount: "connector-pki", ClientRole: "connector-client", ServerRole: "connector-server"}}
	selection := contracts.FederationProviderAuthentication{AuthMount: "federation-auth", AuthMountAccessor: "auth_kubernetes_1",
		Namespace:        contracts.WorkerObjectReference{Name: "asservat", UID: "10000000-0000-4000-8000-000000000003"},
		ServiceAccount:   contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(installation), UID: "10000000-0000-4000-8000-000000000004"},
		AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: "10000000-0000-4000-8000-000000000005"}}
	recipe, err := providerconfig.FederationProviderRecipeFor(in, selection)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = &recipe.Profile
	jwt := ownerProviderTestJWT(time.Now().Add(600 * time.Second))
	purpose := map[string]string{}
	for _, role := range recipe.Roles {
		purpose[role.Name] = role.Purpose
	}
	var mu sync.Mutex
	var logins int
	var cipher string
	issue := map[string]time.Time{}
	const entity = "10000000-0000-4000-8000-000000000008"
	meta := func(role string) map[string]string {
		return map[string]string{"role": role, "service_account_name": selection.ServiceAccount.Name, "service_account_uid": selection.ServiceAccount.UID, "service_account_namespace": selection.Namespace.Name, "service_account_secret_name": ""}
	}
	tlsFixture.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		at, token := time.Now(), r.Header.Get("X-Vault-Token")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/auth/federation-auth/login":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || purpose[body["role"]] == "" || body["jwt"] != string(jwt) {
				w.WriteHeader(403)
				return
			}
			logins++
			issue[body["role"]] = at.Truncate(time.Second)
			auth := ownerProviderAuthReply{ClientToken: body["role"], Accessor: "accessor-" + body["role"], Policies: []string{body["role"]}, TokenPolicies: []string{body["role"]}, Metadata: meta(body["role"]), Orphan: true, EntityID: entity, LeaseDuration: 300, Renewable: true, Type: "service"}
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Auth: &auth})
		case "GET /v1/auth/token/lookup-self":
			issued, known := issue[token]
			if !known {
				w.WriteHeader(403)
				return
			}
			v := initialTokenLookup{ID: token, Accessor: "accessor-" + token, Policies: []string{token}, Path: "auth/federation-auth/login", Meta: meta(token), Display: "kubernetes-federation", Orphan: true, Creation: issued.Unix(), CreationTTL: 300, Expire: issued.Add(300 * time.Second), TTL: int64(issued.Add(300*time.Second).Sub(at) / time.Second), MaxTTL: 900, Entity: entity, Type: "service", Renewable: true, Issued: issued}
			raw, _ := json.Marshal(v)
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Data: raw})
		case "POST /v1/auth/token/revoke-self":
			w.WriteHeader(204)
		default:
			want := map[string]string{"audit-wrap": "/v1/audit/encrypt/federation", "audit-unwrap": "/v1/audit/decrypt/federation", "client-sign": "/v1/connector-pki/sign/connector-client", "server-sign": "/v1/connector-pki/sign/connector-server"}[purpose[token]]
			if want == "" || r.URL.Path != want {
				t.Error("cross-purpose credential reached the provider", r.URL.Path)
				w.WriteHeader(403)
				return
			}
			var body map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&body)
			if purpose[token] == "audit-wrap" {
				_ = json.Unmarshal(body["plaintext"], &cipher)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "synthetic-ciphertext"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": cipher}})
		}
	})
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, contracts.FederationProviderTokenFile), jwt, 0o400); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	var current sync.Mutex
	proofOK := false
	proof := func(context.Context) (time.Time, error) {
		current.Lock()
		defer current.Unlock()
		if !proofOK {
			return time.Time{}, ErrKeyService
		}
		return time.Now().Add(5 * time.Second), nil
	}
	s, err := NewInstalledFederationProviderEffects(context.Background(), in, files, proof)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.CloseAndJoin(context.Background()) }()
	short, end := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer end()
	if s.Prime(short) == nil || logins != 0 {
		t.Fatal("logged in without a current proof", logins)
	}
	current.Lock()
	proofOK = true
	current.Unlock()
	if err = s.Prime(context.Background()); err != nil || logins != 4 {
		t.Fatal("prime did not fund exactly four purposes", err, logins)
	}
	sealed, err := s.Sealer().Seal(context.Background(), []byte("synthetic-keyset"), []byte("binding"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := s.Opener().Open(context.Background(), sealed, []byte("binding")); err != nil || string(opened) != "synthetic-keyset" {
		t.Fatal("audit codec did not roundtrip", err)
	}
	if _, err = s.ConnectorIssuer("owner", value.ConnectorCredentialProfile{}); err == nil {
		t.Fatal("unknown issuer usage accepted")
	}
	if !strings.HasPrefix(recipe.Roles[2].Name, "asservat-federation-") {
		t.Fatal("unexpected role naming")
	}
}
