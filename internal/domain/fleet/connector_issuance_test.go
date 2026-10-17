package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestConnectorRenewalRetainsOriginalBootstrapAnchor(t *testing.T) {
	n := time.Date(2026, 10, 12, 12, 7, 3, 123000000, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	p := ConnectorCredentialProcess{BootstrapID: id, Binding: PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute).Truncate(time.Second)}
	if !p.Valid() {
		t.Fatal("original process invalid")
	}
	original := p.InitialCertificateNotAfter
	for _, at := range []time.Time{n, n.Add(time.Second), original.Add(-time.Minute - time.Nanosecond)} {
		epoch, end, e := p.Window(at)
		if e != nil || epoch != 0 || !end.Equal(original) {
			t.Fatal("initial retry changed anchor", at, epoch, end, e)
		}
	}
	for _, at := range []time.Time{original.Add(-time.Minute), original, original.Add(28 * time.Minute)} {
		epoch, end, e := p.Window(at)
		if e != nil || epoch != 1 || !end.Equal(original.Add(30*time.Minute)) {
			t.Fatal("next period differs", at, epoch, end, e)
		}
	}
	later := time.Date(2600, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, end, e := p.Window(later); e != nil || !end.After(later) || end.After(later.Add(31*time.Minute)) {
		t.Fatal("period arithmetic overflow", end, e)
	}
	bad := p
	bad.InitialCertificateNotAfter = original.Add(time.Second)
	if bad.Valid() {
		t.Fatal("bootstrap expiry extended")
	}
	bad = p
	bad.ServerKeyDigest = bad.ClientKeyDigest
	if bad.Valid() {
		t.Fatal("client/server key reused")
	}
	if _, _, e := p.Window(n.Add(-time.Nanosecond)); e == nil {
		t.Fatal("before admission accepted")
	}
}

func TestConnectorAutomaticProcessKeepsOriginalRetirementBound(t *testing.T) {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	p := ConnectorCredentialProcess{Binding: b, Attested: &ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute), RunUntil: n.Add(45 * time.Minute)}
	if !p.Valid() {
		t.Fatal("bounded automatic process rejected")
	}
	if epoch, end, e := p.Window(n.Add(35 * time.Minute)); e != nil || epoch != 1 || !end.Equal(p.RunUntil) {
		t.Fatal("final leaf extends original process backing", epoch, end, e)
	}
	if _, _, e := p.Window(p.RunUntil); e == nil {
		t.Fatal("expired process can sign")
	}
	q := p
	q.RunUntil = time.Time{}
	if q.Valid() {
		t.Fatal("automatic process without original retirement bound")
	}
	q = p
	q.BootstrapID = id
	if q.Valid() {
		t.Fatal("invented legacy bootstrap mixed into attested process")
	}
}
