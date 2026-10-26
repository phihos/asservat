package bootstrap

import (
	"testing"
	"time"
)

// Kubelet's jittered Pod resync (1.5 x default 1m syncFrequency) plus cache
// propagation must fit; the wait itself stays finite.
func TestProjectionMountWaitCoversKubeletResync(t *testing.T) {
	if projectionMountWait < 90*time.Second+15*time.Second || projectionMountWait > 3*time.Minute {
		t.Fatalf("projection mount wait %s outside kubelet propagation bound", projectionMountWait)
	}
}
