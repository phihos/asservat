package mtls

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
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
	p.ControlDigest, _ = WorkerControlDigest(map[string]string{"worker.json": string(first)})
	roots, err := catalog.IssuerRoots(p, now)
	if err != nil || !roots.Equal(a.roots) {
		t.Fatal("first cluster", err)
	}
	p.ClusterID = ownerOtherID
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("accepted another cluster's digest")
	}
	p.ControlDigest, _ = WorkerControlDigest(map[string]string{"worker.json": string(second)})
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
		t.Fatal("duplicate control accepted")
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
	p.ControlDigest = artifact.Digest{9}
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("unknown control accepted")
	}
	if err = catalog.Replace(nil); err != nil {
		t.Fatal(err)
	}
	p.ControlDigest, _ = WorkerControlDigest(map[string]string{"worker.json": string(first)})
	p.ClusterID = ownerTestID
	if _, err = catalog.IssuerRoots(p, now); err == nil {
		t.Fatal("removed trust accepted")
	}
}

func TestOwnerForwarderMultipleWorkerClusters(t *testing.T) {
	f := newForwardLab(t, "ok")
	firstCA := f.workerCA
	first := workerTrustDocument(t, ownerTestID, firstCA)
	secondCA := newOwnerTestCA(t, time.Now())
	second := workerTrustDocument(t, ownerOtherID, secondCA)
	if err := f.forwarder.config.WorkerTrust.Replace([][]byte{first, second}); err != nil {
		t.Fatal(err)
	}
	for i, cluster := range []string{ownerTestID, ownerOtherID} {
		if i > 0 {
			deadline := time.Now().Add(time.Second)
			for f.released.Load() != int32(i) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if f.released.Load() != int32(i) {
				t.Fatal("previous receiver not released")
			}
		}
		f.worker.Intent.Profile.ClusterID = cluster
		f.worker.Binding.ClusterID = cluster
		raw := first
		if i > 0 {
			raw = second
			f.workerCA = secondCA
		}
		f.worker.Intent.Profile.ControlDigest, _ = WorkerControlDigest(map[string]string{"worker.json": string(raw)})
		out, err := f.forwarder.ForwardWorkerEnrollment(context.Background(), ownerTestID, f.worker.Intent.SessionID, f.worker.Intent.ID, []byte("synthetic.pod.token"), f.csr)
		if err != nil || !out.Peer.Valid(time.Now()) {
			t.Fatal("cluster forwarding", cluster, err)
		}
	}
}

func TestOwnerForwarderRejectsChangedWorkerTrust(t *testing.T) {
	for _, mode := range []string{"missing-before", "foreign-cluster", "removed-after", "profile-after", "foreign-installation", "other-cluster-root"} {
		t.Run(mode, func(t *testing.T) {
			f := newForwardLab(t, "ok")
			original := f.forwarder.config.Workers
			if mode == "other-cluster-root" {
				originalControl := workerTrustDocument(t, ownerTestID, f.workerCA)
				other := newOwnerTestCA(t, time.Now())
				if err := f.forwarder.config.WorkerTrust.Replace([][]byte{originalControl, workerTrustDocument(t, ownerOtherID, other)}); err != nil {
					t.Fatal(err)
				}
				f.workerCA = other
			}
			if mode == "missing-before" {
				if err := f.forwarder.config.WorkerTrust.Replace(nil); err != nil {
					t.Fatal(err)
				}
			}
			f.forwarder.config.Workers = forwardWorkers(func(ctx context.Context, s, w string) (value.DownloadWorkerIdentity, error) {
				o, err := original.ReadDownloadWorkerEnrollment(ctx, s, w)
				if mode == "foreign-cluster" {
					o.Worker.Intent.Profile.ClusterID = ownerOtherID
					o.Worker.Binding.ClusterID = ownerOtherID
				}
				if mode == "foreign-installation" {
					o.Worker.Intent.Profile.InstallationID = ownerOtherID
				}
				if f.requests.Load() > 0 {
					if mode == "removed-after" {
						if e := f.forwarder.config.WorkerTrust.Replace(nil); e != nil {
							t.Fatal(e)
						}
					}
					if mode == "profile-after" {
						o.Worker.Intent.Profile.ControlDigest = artifact.Digest{11}
					}
				}
				return o, err
			})
			if _, err := f.forwarder.ForwardWorkerEnrollment(context.Background(), ownerTestID, f.worker.Intent.SessionID, f.worker.Intent.ID, []byte("synthetic.pod.token"), f.csr); err == nil {
				t.Fatal("changed trust accepted")
			}
			if (mode == "missing-before" || mode == "foreign-cluster" || mode == "foreign-installation") && f.requests.Load() != 0 {
				t.Fatal("token sent before trust resolved")
			}
		})
	}
}
