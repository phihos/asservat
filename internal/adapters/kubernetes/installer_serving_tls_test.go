package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func installerServingTLSFixture(t *testing.T, host string, at time.Time, rootLifetime ...time.Duration) (cert, key, ca []byte) {
	t.Helper()
	issue := func(template, parent *x509.Certificate, pub *ecdsa.PublicKey, signing *ecdsa.PrivateKey) []byte {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signing)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	newKey := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	rootKey, intermediateKey, leafKey := newKey(), newKey(), newKey()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic serving CA"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if len(rootLifetime) != 0 {
		root.NotAfter = at.Add(rootLifetime[0])
	}
	ca = issue(root, root, &rootKey.PublicKey, rootKey)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic intermediate"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediatePEM := issue(intermediate, root, &intermediateKey.PublicKey, rootKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), DNSNames: []string{host}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert = append(issue(leaf, intermediate, &leafKey.PublicKey, intermediateKey), intermediatePEM...)
	encoded, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	return
}

func TestInstallerServingTLSValidatesFullCurrentIdentity(t *testing.T) {
	now := time.Now().UTC()
	cert, key, ca := installerServingTLSFixture(t, "federation.example.test", now)
	_, otherKey, otherCA := installerServingTLSFixture(t, "other.example.test", now)
	shortCACert, shortCAKey, shortCA := installerServingTLSFixture(t, "federation.example.test", now, 30*time.Minute)
	if _, err := ValidateInstallerServingTLS(cert, key, ca, "federation.example.test", now); err != nil {
		t.Fatal("valid intermediate chain", err)
	}
	for _, tc := range []struct {
		name          string
		cert, key, ca []byte
		host          string
		at            time.Time
	}{
		{"wrong-host", cert, key, ca, "other.example.test", now},
		{"wrong-key", cert, otherKey, ca, "federation.example.test", now},
		{"wrong-CA", cert, key, otherCA, "federation.example.test", now},
		{"expired-leaf", cert, key, ca, "federation.example.test", now.Add(time.Hour)},
		{"future-chain", cert, key, ca, "federation.example.test", now.Add(-2 * time.Minute)},
		{"expired-CA-with-current-leaf", shortCACert, shortCAKey, shortCA, "federation.example.test", now.Add(45 * time.Minute)},
		{"non-CA-root", cert, key, cert, "federation.example.test", now},
		{"trailing-certificate-junk", append(append([]byte{}, cert...), []byte("junk")...), key, ca, "federation.example.test", now},
		{"leading-key-junk", cert, append([]byte("junk"), key...), ca, "federation.example.test", now},
		{"second-key", cert, append(append([]byte{}, key...), otherKey...), ca, "federation.example.test", now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateInstallerServingTLS(tc.cert, tc.key, tc.ca, tc.host, tc.at); err == nil {
				t.Fatal("invalid serving identity accepted")
			}
		})
	}
}

func TestInstallerServingTLSCreatesReopensAndReadsBothFixedSecrets(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	installation := ownerID(1)
	fc, fk, fca := installerServingTLSFixture(t, "federation.example.test", time.Now())
	kc, kk, kca := installerServingTLSFixture(t, "keys.example.test", time.Now())
	files := map[string][]byte{contracts.InstallerInboxFederationTLSCertificate: fc, contracts.InstallerInboxFederationTLSKey: fk, contracts.InstallerInboxFederationTLSCA: fca,
		contracts.InstallerInboxKeyServiceTLSCertificate: kc, contracts.InstallerInboxKeyServiceTLSKey: kk, contracts.InstallerInboxKeyServiceTLSCA: kca}
	plan := contracts.InstallerServingTLSPlan{FederationServerName: "federation.example.test", KeyServiceServerName: "keys.example.test"}
	ensure := func() error {
		return EnsureInstallerServingTLS(context.Background(), config, "hub", installation, plan, files)
	}
	if err := ensure(); err != nil {
		t.Fatal(err)
	}
	if err := ensure(); err != nil {
		t.Fatal("exact reopen", err)
	}
	if roots, err := ReadFederationServingRoots(context.Background(), config, "hub", installation, plan.FederationServerName); err != nil || len(roots) != 1 {
		t.Fatal("federation consumer", err)
	}
	if roots, err := ReadKeyServiceServingRoots(context.Background(), config, "hub", installation, plan.KeyServiceServerName); err != nil || len(roots) != 1 {
		t.Fatal("key-service consumer", err)
	}
	path := "/api/v1/namespaces/hub/secrets/" + contracts.FederationServingSecretName(installation)
	api.mu.Lock()
	before := api.objects[path]
	api.mu.Unlock()
	changed := map[string][]byte{}
	for k, v := range files {
		changed[k] = v
	}
	changed[contracts.InstallerInboxFederationTLSCertificate], changed[contracts.InstallerInboxFederationTLSKey], changed[contracts.InstallerInboxFederationTLSCA] = installerServingTLSFixture(t, plan.FederationServerName, time.Now())
	if err := EnsureInstallerServingTLS(context.Background(), config, "hub", installation, plan, changed); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("replaced existing serving identity", err)
	}
	api.mu.Lock()
	after := api.objects[path]
	api.mu.Unlock()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing Secret mutated")
	}
}

func TestInstallerServingTLSPreflightRefusesBeforeAnyAPI(t *testing.T) {
	cert, key, ca := installerServingTLSFixture(t, "federation.example.test", time.Now())
	valid := map[string][]byte{contracts.InstallerInboxFederationTLSCertificate: cert, contracts.InstallerInboxFederationTLSKey: key, contracts.InstallerInboxFederationTLSCA: ca}
	for _, mode := range []string{"incomplete", "unexpected", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			files := map[string][]byte{}
			for k, v := range valid {
				files[k] = v
			}
			plan := contracts.InstallerServingTLSPlan{FederationServerName: "federation.example.test"}
			switch mode {
			case "incomplete":
				delete(files, contracts.InstallerInboxFederationTLSCA)
			case "unexpected":
				plan = contracts.InstallerServingTLSPlan{}
			case "wrong-host":
				plan.FederationServerName = "wrong.example.test"
			}
			if err := EnsureInstallerServingTLS(context.Background(), config, "hub", ownerID(1), plan, files); err == nil || calls != 0 {
				t.Fatal("invalid input reached API", err, calls)
			}
		})
	}
}

func TestInstallerServingTLSUnknownCreateOnlyReopensExact(t *testing.T) {
	cert, key, ca := installerServingTLSFixture(t, "federation.example.test", time.Now())
	files := map[string][]byte{contracts.InstallerInboxFederationTLSCertificate: cert, contracts.InstallerInboxFederationTLSKey: key, contracts.InstallerInboxFederationTLSCA: ca}
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "changed"}[changed], func(t *testing.T) {
			var stored *core.Secret
			posts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					posts++
					_ = json.NewDecoder(r.Body).Decode(&stored)
					stored.UID = types.UID(ownerID(9))
					if changed {
						stored.Data["extra"] = []byte("refuse")
					}
					w.WriteHeader(500)
					_ = json.NewEncoder(w).Encode(meta.Status{Status: meta.StatusFailure, Reason: meta.StatusReasonInternalError, Code: 500})
					return
				}
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, contracts.FederationServingSecretName(ownerID(1))) {
					t.Error("unexpected API", r.Method, r.URL.Path)
				}
				if stored == nil {
					w.WriteHeader(404)
					_ = json.NewEncoder(w).Encode(meta.Status{Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
					return
				}
				_ = json.NewEncoder(w).Encode(stored)
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			err := EnsureInstallerServingTLS(context.Background(), config, "hub", ownerID(1), contracts.InstallerServingTLSPlan{FederationServerName: "federation.example.test"}, files)
			if posts != 1 || changed && !errors.Is(err, cfg.ErrChanged) || !changed && err != nil {
				t.Fatal("unknown create replay", posts, err)
			}
		})
	}
}

func TestInstallerInboxServingTLSIsCompleteAndPhaseThreeOnly(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	installation := ownerID(1)
	cert, key, ca := installerServingTLSFixture(t, "federation.example.test", time.Now())
	files := map[string][]byte{contracts.InstallerInboxFederationTLSCertificate: cert, contracts.InstallerInboxFederationTLSKey: key, contracts.InstallerInboxFederationTLSCA: ca}
	write := func(phase int, material map[string][]byte) error {
		return WriteInstallerInbox(context.Background(), config, "release", installation, phase, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, InstallerInboxMaterial{ServingTLS: material})
	}
	if err := write(3, files); err != nil {
		t.Fatal(err)
	}
	inbox, err := ReadInstallerInbox(context.Background(), config, "release", installation, 3)
	if err != nil || !reflect.DeepEqual(inbox.ServingTLS, files) {
		t.Fatal("serving material did not roundtrip", err)
	}
	if err := write(2, files); err == nil {
		t.Fatal("TLS bundle accepted outside phase three")
	}
	path := "/api/v1/namespaces/release/secrets/" + contracts.InstallerInboxName(installation)
	api.mu.Lock()
	delete(api.objects[path]["data"].(map[string]any), contracts.InstallerInboxFederationTLSKey)
	api.mu.Unlock()
	if _, err := ReadInstallerInbox(context.Background(), config, "release", installation, 3); err == nil {
		t.Fatal("incomplete TLS bundle returned")
	}
}
