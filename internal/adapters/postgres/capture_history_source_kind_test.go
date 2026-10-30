package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestCaptureHistoryKeepsFiniteActionKinds(t *testing.T) {
	if kinds := historyActionKinds(artifact.ContextExpectation{}); len(kinds) != 1 || kinds[0] != "kubernetesSnapshot" {
		t.Fatal("ordinary metadata action changed", kinds)
	}
	if kinds := historyActionKinds(artifact.ContextExpectation{Recording: &artifact.Recording{}}); len(kinds) != 1 || kinds[0] != "packetCapture" {
		t.Fatal("finite recorder action changed", kinds)
	}
}
