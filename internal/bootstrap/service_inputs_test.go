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
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

var serviceTestIDs = contracts.ServiceIDs{InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", PermissionRootID: "10000000-0000-4000-8000-000000000003", IssuerEpoch: "10000000-0000-4000-8000-000000000004"}

// serviceTestRoots writes the mounted ids directory and returns it opened.
func serviceTestIDsRoot(t *testing.T, ids contracts.ServiceIDs) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{"installationID": ids.InstallationID, "clusterID": ids.ClusterID, "permissionRootID": ids.PermissionRootID, "issuerEpoch": ids.IssuerEpoch, "browserRootID": "unused"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// serviceTestConfigRoot writes config.json from v and returns its root.
func serviceTestConfigRoot(t *testing.T, v any) *os.Root {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, contracts.ServiceConfigFile), raw, 0o400); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func serviceTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestServiceIDsAreGeneratedUUIDs(t *testing.T) {
	got, err := readServiceIDs(context.Background(), serviceTestIDsRoot(t, serviceTestIDs))
	if err != nil || got != serviceTestIDs {
		t.Fatal("ids", got, err)
	}
	bad := serviceTestIDs
	bad.IssuerEpoch = "epoch"
	if _, err = readServiceIDs(context.Background(), serviceTestIDsRoot(t, bad)); err == nil {
		t.Fatal("non-UUID issuer epoch accepted")
	}
}

func TestServicePEMRootsAreCABundles(t *testing.T) {
	ca := serviceTestCAPEM(t)
	if roots, err := servicePEMRoots(append(append([]byte{}, ca...), ca...)); err == nil {
		t.Fatal("duplicate root accepted", roots)
	}
	if roots, err := servicePEMRoots(ca); err != nil || len(roots) != 1 {
		t.Fatal("single CA", err)
	}
	for name, b := range map[string][]byte{"empty": nil, "trailing text": append(append([]byte{}, ca...), "junk"...)} {
		if _, err := servicePEMRoots(b); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

// Client CAs come from the provider's unauthenticated PKI ca/pem endpoint.
func TestPKIRootsReadTheMountCA(t *testing.T) {
	ca := serviceTestCAPEM(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/worker-pki/ca/pem" || r.Header.Get("X-Vault-Token") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write(ca)
	}))
	defer server.Close()
	provider := [][]byte{server.Certificate().Raw}
	roots, err := readPKIRoots(context.Background(), server.URL, provider, "worker-pki")
	block, _ := pem.Decode(ca)
	if err != nil || len(roots) != 1 || string(roots[0]) != string(block.Bytes) {
		t.Fatal("pki roots", err)
	}
	if _, err = readPKIRoots(context.Background(), server.URL, provider, "connector-pki"); err == nil {
		t.Fatal("refused mount read accepted")
	}
	if _, err = readPKIRoots(context.Background(), server.URL, provider, "../sys"); err == nil {
		t.Fatal("unsafe mount accepted")
	}
}

// Catalog slots add their own topology to the configured ones; a slot for
// another cluster, or a cluster or name used twice, is refused.
func TestServiceTopologyPinsUnionCatalogSlots(t *testing.T) {
	const regional = "10000000-0000-4000-8000-0000000000b1"
	fixed := []contracts.ServiceTopology{{TargetClusterID: serviceTestIDs.ClusterID, Name: "hub-topology"}}
	slot := contracts.OwnerPublicCluster{ClusterID: regional, Topology: contracts.OwnerNativeTopology{TargetClusterID: regional, Name: "cluster-1-topology"}}
	if pins, err := serviceTopologyPins(nil, nil); err != nil || len(pins) != 0 {
		t.Fatal("empty union", pins, err)
	}
	pins, err := serviceTopologyPins(fixed, []contracts.OwnerPublicCluster{slot})
	if err != nil || len(pins) != 2 || pins[1].TargetClusterID != regional || pins[1].Name != slot.Topology.Name {
		t.Fatal("union", pins, err)
	}
	for name, mutate := range map[string]func(*contracts.OwnerPublicCluster){
		"other cluster": func(s *contracts.OwnerPublicCluster) { s.Topology.TargetClusterID = serviceTestIDs.ClusterID },
		"fixed cluster": func(s *contracts.OwnerPublicCluster) {
			s.ClusterID, s.Topology.TargetClusterID = serviceTestIDs.ClusterID, serviceTestIDs.ClusterID
		},
		"fixed topology": func(s *contracts.OwnerPublicCluster) { s.Topology.Name = "hub-topology" },
		"unsafe name":    func(s *contracts.OwnerPublicCluster) { s.Topology.Name = "../x" },
	} {
		changed := slot
		mutate(&changed)
		if _, err = serviceTopologyPins(fixed, []contracts.OwnerPublicCluster{changed}); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

func TestPlatformWorkloadDigestSeparatesFields(t *testing.T) {
	a := contracts.PlatformWorkloadDigest("c", "ns", "hub-api")
	if a == contracts.PlatformWorkloadDigest("c", "nsh", "ub-api") || a == contracts.PlatformWorkloadDigest("c", "ns", "hub-api2") || a != contracts.PlatformWorkloadDigest("c", "ns", "hub-api") {
		t.Fatal("digest is not a deterministic field-separated value")
	}
}
