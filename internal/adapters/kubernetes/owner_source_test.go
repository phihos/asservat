package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/configuration"
)

const ownerSourceJSON = `{"deployment":"asservat-hub-api","format":"asservat-hub-owner-source/v1","nativeBootstrap":"owner-bootstrap/v1","nativeCandidateLimit":1024,"nativePort":9444,"operationPort":9448,"port":9443,"revision":1,"service":"asservat-hub-api-owner","serviceAccount":"asservat-hub-api","suspended":false}`

func ownerSourceCA(t *testing.T, now time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owner-pki"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The Helm-rendered owner source holds names only; the reader completes it
// with the generated IDs, the objects' UIDs by name and the owner PKI CA, and
// reads UIDs and roots once.
func TestOwnerSourceReaderCompletesHelmSource(t *testing.T) {
	const ns, nsUID, cmUID = "asservat-system", "a0000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000002"
	const installation, epoch = "a0000000-0000-4000-8000-000000000003", "a0000000-0000-4000-8000-000000000004"
	uids := map[string]string{"/api/v1/namespaces/asservat-system/services/asservat-hub-api-owner": "a0000000-0000-4000-8000-000000000005",
		"/apis/apps/v1/namespaces/asservat-system/deployments/asservat-hub-api": "a0000000-0000-4000-8000-000000000006",
		"/api/v1/namespaces/asservat-system/serviceaccounts/asservat-hub-api":   "a0000000-0000-4000-8000-000000000007"}
	source := ownerSourceJSON
	var uidReads atomic.Int32
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/namespaces/" + ns:
			permissionReply(w, permissionNamespace(ns, nsUID))
		case "/api/v1/namespaces/" + ns + "/configmaps/asservat-owner-source":
			permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "asservat-owner-source", "namespace": ns, "uid": cmUID, "resourceVersion": "1"}, "data": map[string]string{"owner-pool.json": source}})
		default:
			uid, ok := uids[r.URL.Path]
			if !ok {
				return false
			}
			uidReads.Add(1)
			permissionReply(w, map[string]any{"metadata": map[string]any{"uid": uid}})
		}
		return true
	})
	client, err := NewPermissionClient(f.config, permissionCluster, value.NamespaceRef{Name: ns, UID: nsUID}, f.client.now)
	if err != nil {
		t.Fatal(err)
	}
	ca := ownerSourceCA(t, f.client.now())
	var rootReads atomic.Int32
	reader, err := NewOwnerSourceReader(client, "asservat-owner-source", cmUID, installation, epoch, func(context.Context) ([][]byte, error) {
		rootReads.Add(1)
		return [][]byte{ca}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		o, err := reader.ReadOwnerConfiguration(context.Background())
		p := o.Configuration.Pool
		if err != nil || p.InstallationID != installation || p.ClusterID != permissionCluster || p.IssuerEpoch != epoch || p.NamespaceUID != nsUID ||
			p.ServiceUID != uids["/api/v1/namespaces/asservat-system/services/asservat-hub-api-owner"] || p.DeploymentUID != uids["/apis/apps/v1/namespaces/asservat-system/deployments/asservat-hub-api"] ||
			p.AccountUID != uids["/api/v1/namespaces/asservat-system/serviceaccounts/asservat-hub-api"] || o.Configuration.Revision.UID != cmUID || len(o.Configuration.IssuerRoots) != 1 || p.OperationListenPort() != 9448 {
			t.Fatal("owner source not completed", err, p)
		}
	}
	if uidReads.Load() != 3 || rootReads.Load() != 1 {
		t.Fatal("UIDs and roots not reused", uidReads.Load(), rootReads.Load())
	}
	for name, bad := range map[string]string{
		"generated-id": strings.Replace(ownerSourceJSON, `"format"`, `"installationID":"`+installation+`","format"`, 1),
		"uid":          strings.Replace(ownerSourceJSON, `"service":"asservat-hub-api-owner"`, `"service":{"name":"asservat-hub-api-owner","uid":"x"}`, 1),
		"format":       strings.Replace(ownerSourceJSON, "asservat-hub-owner-source/v1", "asservat-hub-owner-configuration/v1", 1),
		"omitted":      strings.Replace(ownerSourceJSON, `"operationPort":9448,`, ``, 1),
		"port":         strings.Replace(ownerSourceJSON, `"port":9443`, `"port":80`, 1),
	} {
		source = bad
		if _, err := reader.ReadOwnerConfiguration(context.Background()); err == nil {
			t.Fatal("accepted", name)
		}
	}
}
