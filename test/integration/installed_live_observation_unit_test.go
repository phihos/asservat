package integration

import (
	"testing"
)

func TestInstalledLiveObservationUsesFastOriginalTopology(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "live-observation")
	if !installedFastFixture() {
		t.Fatal("live feature would repeat unrelated installation qualification instead of the original fast real installer")
	}
}
