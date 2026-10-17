package fleet

import (
	"testing"
	"time"
)

func TestOwnerObservationReadyGroupsRetainCompleteOriginalMembers(t *testing.T) {
	now := time.Now().UTC()
	candidates := observationCandidateValues(17, 32, now)
	dead := candidates.Owners[0]
	dead.PodUID = observationOtherID
	dead.ProcessEpoch = observationOtherID
	candidates.Owners = append(candidates.Owners, dead)
	group := OwnerObservationCandidateGroups{Candidates: candidates, Groups: []OwnerObservationCandidateGroup{{PodUID: observationTestID, Owners: append([]OwnerBinding(nil), candidates.Owners[:17]...)}}, EndpointResourceVersion: "20", ObservedAt: now.Add(time.Millisecond), ValidUntil: now.Add(800 * time.Millisecond)}
	at := now.Add(2 * time.Millisecond)
	if !group.Valid(at) {
		t.Fatal("complete members with absent retained Pod rejected")
	}
	for name, change := range map[string]func(*OwnerObservationCandidateGroups){
		"dropped-process":   func(v *OwnerObservationCandidateGroups) { v.Groups[0].Owners = v.Groups[0].Owners[1:] },
		"duplicate-process": func(v *OwnerObservationCandidateGroups) { v.Groups[0].Owners[16] = v.Groups[0].Owners[0] },
		"wrong-pod":         func(v *OwnerObservationCandidateGroups) { v.Groups[0].PodUID = observationOtherID },
		"invented-process":  func(v *OwnerObservationCandidateGroups) { v.Groups[0].Owners[0].ProcessEpoch = observationOtherID },
		"empty-ready":       func(v *OwnerObservationCandidateGroups) { v.Groups = nil },
		"missing-version":   func(v *OwnerObservationCandidateGroups) { v.EndpointResourceVersion = "" },
		"renewed-sql":       func(v *OwnerObservationCandidateGroups) { v.ValidUntil = v.Candidates.ValidUntil.Add(time.Nanosecond) },
		"pre-sql":           func(v *OwnerObservationCandidateGroups) { v.ObservedAt = now.Add(-time.Nanosecond) },
		"unopted":           func(v *OwnerObservationCandidateGroups) { v.Candidates.Pool.NativeCandidateLimit = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			v := group.Clone()
			change(&v)
			if v.Valid(at) {
				t.Fatal("incomplete or changed routing filter accepted")
			}
		})
	}
	clone := group.Clone()
	clone.Groups[0].Owners[0].ProcessEpoch = observationOtherID
	clone.Candidates.Owners[0].ProcessEpoch = observationOtherID
	if !group.Valid(at) {
		t.Fatal("caller mutated original complete candidate provenance")
	}
	if group.Valid(group.ValidUntil) {
		t.Fatal("Ready observation refreshed at receipt")
	}
}
