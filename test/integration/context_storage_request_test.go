package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

type storageRequestProcessing struct{}

func (storageRequestProcessing) ContextProcessingCoverage(c context.Context, r value.ProcessingCoverageRequest, recovery artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(5 * time.Second)
	if deadline, ok := c.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	if recovery.FreshUntil.Before(until) {
		until = recovery.FreshUntil
	}
	return value.ProcessingCoverage{Request: r, ObservedAt: now, FreshUntil: until}, c.Err()
}

func TestStorageRequestProcessingPreservesOriginalBounds(t *testing.T) {
	for _, contextFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery-first", true: "caller-first"}[contextFirst], func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			caller, recovery := now.Add(time.Second), now.Add(750*time.Millisecond)
			if contextFirst {
				caller, recovery = recovery, caller
			}
			c, cancel := context.WithDeadline(t.Context(), caller)
			defer cancel()
			r := value.ProcessingCoverageRequest{RootID: custodyID(), Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, AnchorAt: now, DeleteBy: now.Add(time.Hour)}
			r.Target.ClusterID, r.Target.NamespaceUID, r.Target.WorkloadUID, r.Target.PodUID = r.Location.ClusterID, custodyID(), custodyID(), custodyID()
			got, err := (storageRequestProcessing{}).ContextProcessingCoverage(c, r, artifact.RecoveryProof{FreshUntil: recovery})
			if err != nil || !got.Current(time.Now()) || got.Request != r || got.FreshUntil.After(caller) || got.FreshUntil.After(recovery) {
				t.Fatal("synthetic processing exceeded original consumer proof bounds", err)
			}
		})
	}
}
