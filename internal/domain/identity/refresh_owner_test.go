package identity

import (
	"testing"
	"time"
)

func TestRefreshDemandOriginalGraceAndExactResponse(t *testing.T) {
	n := time.Now()
	id := "11111111-1111-4111-8111-111111111111"
	owner := RefreshOwnerRef{RootID: id, Epoch: id, OwnerID: id, InstallationID: id, ClusterID: id, PodUID: id, ProcessEpoch: id, SessionID: [32]byte{1}, Generation: 1}
	v := RefreshDemand{Owner: RefreshOwnerObservation{Owner: owner, SessionEnd: n.Add(time.Hour), LeaseUntil: n.Add(15 * time.Second), ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, DownloadID: id, HardUntil: n.Add(time.Minute), GraceUntil: n.Add(time.Second)}
	if !v.Valid(n) {
		t.Fatal("original grace denied")
	}
	partial := v
	partial.ResponseID = id
	if partial.Valid(n) {
		t.Fatal("partial response hidden behind grace")
	}
	if v.Valid(n.Add(2 * time.Second)) {
		t.Fatal("ended grace treated as response liveness")
	}
	v.ResponseID = id
	v.ResponseOwnerID = id
	v.ResponseGeneration = 1
	v.ResponseLeaseUntil = n.Add(4 * time.Second)
	if !v.Valid(n.Add(2 * time.Second)) {
		t.Fatal("current exact response denied")
	}
	if v.Valid(n.Add(4 * time.Second)) {
		t.Fatal("expired response lease renewed demand")
	}
	v.ResponseLeaseUntil = n.Add(6 * time.Second)
	if v.Valid(n) {
		t.Fatal("extended response lease accepted")
	}
}
