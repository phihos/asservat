package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func continuationMaterialCertificates(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Now()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"console.example", "federation.example", "keys.example"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

type continuationMaterialFixture struct {
	k       *InstallerContinuation
	secrets map[string]*core.Secret
	calls   int
	mode    string
	cancel  context.CancelFunc
}

func newContinuationMaterialFixture(t *testing.T, bundled bool) *continuationMaterialFixture {
	t.Helper()
	f := &continuationMaterialFixture{secrets: map[string]*core.Secret{}}
	crt, key, ca := continuationMaterialCertificates(t)
	data := map[string][]byte{contracts.OwnerPublicTLSCertificate: crt, contracts.OwnerPublicTLSKey: key, contracts.OwnerPublicClientSecretFile: []byte("external-console-client-secret"), "seal.key": []byte("never-copy-private-seal"), "ca.key": []byte("never-copy-ca-key")}
	keys := contracts.InstallerInboxServingTLSFiles()
	for i := 0; i < 2; i++ {
		data[keys[i*3]] = crt
		data[keys[i*3+1]] = key
		data[keys[i*3+2]] = ca
	}
	f.secrets["operator-material"] = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "operator-material", Namespace: "bootstrap", UID: types.UID(initialBaoState), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: data}
	settings := smallKeycloakTestSettings()
	settings.Namespace = "bootstrap"
	settings.Origin = "https://console.example"
	settings.SecretName = "trial-keycloak-state"
	state, e := BuildSmallKeycloakMaterial(settings, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	state.UID = types.UID(initialBaoAccount)
	state.ResourceVersion = "1"
	f.secrets[state.Name] = state
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls++
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "Bearer synthetic-admin-token" || !strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/bootstrap/secrets/") {
			t.Error("unexpected scope or effect")
			w.WriteHeader(403)
			return
		}
		if f.mode == "redirect" {
			w.Header().Set("Location", "/api/v1/namespaces/foreign/secrets/replacement")
			w.WriteHeader(307)
			return
		}
		if f.mode == "unknown" {
			w.WriteHeader(503)
			return
		}
		if f.mode == "malformed" {
			_, _ = w.Write([]byte(`{"data":`))
			return
		}
		if f.mode == "oversize" {
			_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
			return
		}
		if f.mode == "cancel" {
			f.cancel()
			return
		}
		secret := f.secrets[strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/bootstrap/secrets/")]
		if secret == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(secret)
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	if e = os.WriteFile(filepath.Join(dir, "administrator-token"), []byte("synthetic-admin-token"), 0600); e != nil {
		t.Fatal(e)
	}
	files, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { files.Close() })
	f.k = &InstallerContinuation{in: &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}, input: contracts.InstallerContinuation{Namespace: "bootstrap", MaterialSecretName: "operator-material", Public: &contracts.InstallerPublicSettings{Origin: settings.Origin, Issuer: settings.Hostname + "/realms/" + settings.Realm, ClientID: settings.ConsoleClientID, Promotion: &contracts.InstallerOwnerPromotion{}}}, plan: contracts.InitialPreparer{Plan: contracts.InitialPreparationPlan{RootName: "trial-preparation"}}, bundledIdentity: bundled}
	t.Cleanup(f.k.in.closeHTTP)
	return f
}
func TestSmallOwnerMaterialFiltersAndValidatesRequiredGroups(t *testing.T) {
	for _, bundled := range []bool{false, true} {
		t.Run(map[bool]string{false: "external-identity", true: "bundled-identity"}[bundled], func(t *testing.T) {
			f := newContinuationMaterialFixture(t, bundled)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serving := contracts.InstallerServingTLSPlan{FederationServerName: "federation.example", KeyServiceServerName: "keys.example"}
			got, e := f.k.smallOwnerMaterial(ctx, serving)
			if e != nil || len(got) != 9 {
				t.Fatal("required complete material refused", e, len(got))
			}
			expectedCalls := 1
			if bundled {
				expectedCalls = 2
			}
			if f.calls != expectedCalls {
				t.Fatal("unexpected reads", f.calls)
			}
			if got["seal.key"] != nil || got["ca.key"] != nil {
				t.Fatal("unselected root keys propagated")
			}
			want := f.secrets["operator-material"].Data[contracts.OwnerPublicClientSecretFile]
			if bundled {
				want = f.secrets["trial-keycloak-state"].Data[contracts.SmallKeycloakConsoleSecret]
			}
			if !reflect.DeepEqual(got[contracts.OwnerPublicClientSecretFile], want) {
				t.Fatal("client secret did not come from selected original source")
			}
		})
	}
}
func TestSmallOwnerMaterialNoInputWithoutSelectedConsumers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, e := (&InstallerContinuation{}).smallOwnerMaterial(ctx, contracts.InstallerServingTLSPlan{})
	if e != nil || len(got) != 0 {
		t.Fatal("observation-only owner requires material", e)
	}
	f := newContinuationMaterialFixture(t, false)
	f.k.input.Public.Promotion = nil
	got, e = f.k.smallOwnerMaterial(ctx, contracts.InstallerServingTLSPlan{FederationServerName: "federation.example"})
	if e != nil || len(got) != 3 || f.calls != 1 {
		t.Fatal("serving-only selection copied public/unselected group", e)
	}
}
func TestSmallOwnerMaterialRefusesChangedSourcesWithoutRetry(t *testing.T) {
	for _, mode := range []string{"unknown", "redirect", "malformed", "oversize", "cancel", "name", "namespace", "uid", "rv", "kind", "type", "deleting", "missing", "foreign-host", "partial-group", "missing-secret"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationMaterialFixture(t, false)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			f.cancel = cancel
			m := f.secrets["operator-material"]
			serving := contracts.InstallerServingTLSPlan{FederationServerName: "federation.example"}
			switch mode {
			case "unknown", "redirect", "malformed", "oversize", "cancel":
				f.mode = mode
			case "name":
				m.Name = "foreign"
			case "namespace":
				m.Namespace = "foreign"
			case "uid":
				m.UID = ""
			case "rv":
				m.ResourceVersion = ""
			case "kind":
				m.Kind = "ConfigMap"
			case "type":
				m.Type = core.SecretTypeServiceAccountToken
			case "deleting":
				now := meta.Now()
				m.DeletionTimestamp = &now
			case "missing":
				delete(m.Data, contracts.OwnerPublicTLSKey)
			case "foreign-host":
				f.k.input.Public.Origin = "https://foreign.example"
			case "partial-group":
				delete(m.Data, contracts.InstallerInboxFederationTLSCA)
			case "missing-secret":
				delete(f.secrets, "operator-material")
			}
			got, e := f.k.smallOwnerMaterial(ctx, serving)
			if e == nil || len(got) != 0 || f.calls != 1 {
				t.Fatal("changed/unknown source accepted or retried", e, f.calls)
			}
			if strings.Contains(e.Error(), "never-copy") || strings.Contains(e.Error(), "synthetic-admin") {
				t.Fatal("private material exposed in diagnostic")
			}
		})
	}
}

func TestSmallOwnerMaterialRejectsUnusedAuthorityAndBadRefBeforeRead(t *testing.T) {
	for _, mode := range []string{"bad-name", "canceled", "no-deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationMaterialFixture(t, false)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			switch mode {
			case "bad-name":
				f.k.input.MaterialSecretName = "../foreign"
			case "canceled":
				cancel()
			case "no-deadline":
				ctx = context.Background()
			}
			if got, e := f.k.smallOwnerMaterial(ctx, contracts.InstallerServingTLSPlan{}); e == nil || len(got) != 0 || f.calls != 0 {
				t.Fatal("invalid original scope reached source", e, f.calls)
			}
		})
	}
}
func TestSmallOwnerMaterialBundledIdentityNeverFallsBack(t *testing.T) {
	for _, mode := range []string{"missing-original", "foreign-namespace", "foreign-client", "wrong-role"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationMaterialFixture(t, true)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			switch mode {
			case "missing-original":
				delete(f.secrets, "trial-keycloak-state")
			case "foreign-namespace":
				f.secrets["trial-keycloak-state"].Namespace = "foreign"
			case "foreign-client":
				f.k.input.Public.ClientID = "foreign"
			case "wrong-role":
				f.secrets["trial-keycloak-state"].Labels["asservat.io/private-role"] = "foreign"
			}
			if got, e := f.k.smallOwnerMaterial(ctx, contracts.InstallerServingTLSPlan{}); e == nil || len(got) != 0 || f.calls != 2 {
				t.Fatal("bundled source failed open to supplied external secret", e, f.calls)
			}
		})
	}
}
func TestSmallOwnerMaterialAcceptsNamedTLSSecretAndCurrentPublicLeaf(t *testing.T) {
	f := newContinuationMaterialFixture(t, false)
	f.secrets["operator-material"].Type = core.SecretTypeTLS
	f.secrets["operator-material"].Data[core.TLSCertKey] = f.secrets["operator-material"].Data[contracts.OwnerPublicTLSCertificate]
	f.secrets["operator-material"].Data[core.TLSPrivateKeyKey] = f.secrets["operator-material"].Data[contracts.OwnerPublicTLSKey]
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, e := f.k.smallOwnerMaterial(ctx, contracts.InstallerServingTLSPlan{}); e != nil {
		t.Fatal("named TLS material source refused", e)
	}
	crt, key, _ := continuationMaterialCertificates(t)
	if validateSmallPublicTLS(crt, key, "https://console.example", time.Now().Add(2*time.Hour)) == nil {
		t.Fatal("expired public leaf accepted")
	}
	if validateSmallPublicTLS(crt, append([]byte("unrecognized-prefix\n"), key...), "https://console.example", time.Now()) == nil {
		t.Fatal("unrecognized key prefix accepted")
	}
}
