package mtls

import (
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerRootBoundsAndCurrentValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newOwnerTestCA(t, now)
	if roots, until, err := OwnerTrustRoots([][]byte{ca.cert.Raw}, now); err != nil || roots == nil || !until.Equal(ca.cert.NotAfter) {
		t.Fatal("valid roots", err)
	}
	b := value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID}
	leaf := ca.leaf(t, now, b, true, nil)
	for name, raw := range map[string][][]byte{"empty": nil, "duplicate": {ca.cert.Raw, ca.cert.Raw}, "leaf": leaf.Certificate, "malformed": {{1, 2}}, "oversized": {make([]byte, 16385)}, "too-many": {ca.cert.Raw, ca.cert.Raw, ca.cert.Raw, ca.cert.Raw, ca.cert.Raw}} {
		t.Run(name, func(t *testing.T) {
			if roots, _, err := OwnerTrustRoots(raw, now); err == nil || roots != nil {
				t.Fatal("unsafe root accepted")
			}
		})
	}
	for _, clock := range []time.Time{ca.cert.NotBefore.Add(-time.Second), ca.cert.NotAfter, time.Time{}} {
		if _, _, err := OwnerTrustRoots([][]byte{ca.cert.Raw}, clock); err == nil {
			t.Fatal("root lifetime ignored")
		}
	}
}
