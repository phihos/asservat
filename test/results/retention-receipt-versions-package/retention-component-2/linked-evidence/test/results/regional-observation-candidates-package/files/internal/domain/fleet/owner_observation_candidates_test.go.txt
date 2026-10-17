package fleet

import (
	"fmt"
	"testing"
	"time"
)

func observationCandidateValues(count, limit int, now time.Time) APIContextOwnerCandidates {
	p := ownerObservationFixture(now).Owner.Pool
	p.NativeCandidateLimit = limit
	out := APIContextOwnerCandidates{Pool: p, ObservedAt: now, ValidUntil: now.Add(time.Second)}
	for i := 0; i < count; i++ {
		out.Owners = append(out.Owners, OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: observationTestID, ProcessEpoch: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)})
	}
	return out
}

func TestOwnerObservationCandidateValueKeepsExplicitPopulationAndEveryProcess(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name         string
		count, limit int
		valid        bool
	}{{"legacy16", 16, 0, true}, {"legacy17", 17, 0, false}, {"opted17", 17, 17, true}, {"opted-overflow", 18, 17, false}, {"retained-ceiling", 1024, 1024, true}, {"over-ceiling", 1025, 1024, false}, {"invalid-installed-limit", 0, 1025, false}} {
		t.Run(tc.name, func(t *testing.T) {
			o := observationCandidateValues(tc.count, tc.limit, now)
			if o.Valid(now) != tc.valid {
				t.Fatal("candidate bound", tc.count, tc.limit)
			}
		})
	}
	o := observationCandidateValues(17, 17, now)
	if !o.Valid(now) {
		t.Fatal("different processes in one Pod were silently collapsed")
	}
	o.Owners[16] = o.Owners[0]
	if o.Valid(now) {
		t.Fatal("duplicate process accepted")
	}
	o = observationCandidateValues(17, 17, now)
	o.Owners[16].ClusterID = observationOtherID
	if o.Valid(now) {
		t.Fatal("foreign process accepted")
	}
	o = observationCandidateValues(17, 17, now)
	if o.Valid(o.ValidUntil) {
		t.Fatal("complete original set renewed at expiry")
	}
}
