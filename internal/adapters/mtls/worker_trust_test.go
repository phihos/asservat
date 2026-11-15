package mtls

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func workerTrustDocument(t *testing.T, cluster string, ca ownerTestCA) []byte {
	t.Helper()
	b, err := json.Marshal(contracts.WorkerControl{Format: contracts.WorkerControlFormat, InstallationID: ownerTestID, ClusterID: cluster, Endpoint: "https://enroll.synthetic.invalid", ServerRoots: [][]byte{ca.cert.Raw}, IssuerRoots: [][]byte{ca.cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWorkerTrustCatalogExactSelection(t *testing.T) {
	now := time.Now()
	a, b := newOwnerTestCA(t, now), newOwnerTestCA(t, now)
	first, second := workerTrustDocument(t, ownerTestID, a), workerTrustDocument(t, ownerOtherID, b)
	catalog, err := NewWorkerTrustCatalog(ownerTestID, [][]byte{first, second})
	if err != nil {
		t.Fatal(err)
	}
	p := forwardTestWorker(t).Intent.Profile
	p.ClusterID = ownerTestID
	roots, err := catalog.IssuerRoots(p, now)
	if err != nil || !roots.Equal(a.roots) {
		t.Fatal("first cluster", err)
	}
	p.ClusterID = ownerOtherID
	roots, err = catalog.IssuerRoots(p, now)
	if err != nil || !roots.Equal(b.roots) {
		t.Fatal("second cluster", err)
	}
	roots.AddCert(a.cert)
	again, err := catalog.IssuerRoots(p, now)
	if err != nil || !again.Equal(b.roots) {
		t.Fatal("caller changed catalog trust")
	}
	clear(second)
	if _, err = catalog.IssuerRoots(p, now); err != nil {
		t.Fatal("input retained by reference", err)
	}
	if err = catalog.Replace([][]byte{first, first}); err == nil {
		t.Fatal("two controls of one cluster accepted")
	}
	if _, err = catalog.IssuerRoots(p, now); err != nil {
		t.Fatal("failed replacement erased current catalog", err)
	}
	if _, err = catalog.IssuerRoots(p, b.cert.NotAfter); err == nil {
		t.Fatal("expired root accepted")
	}
	p.InstallationID = ownerOtherID
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("foreign installation accepted")
	}
	p.InstallationID = ownerTestID
	p.ClusterID = ownerOtherID
	if err = catalog.Replace([][]byte{first}); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("cluster without a control accepted")
	}
	if err = catalog.Replace(nil); err != nil {
		t.Fatal(err)
	}
	p.ClusterID = ownerTestID
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("removed trust accepted")
	}
}
