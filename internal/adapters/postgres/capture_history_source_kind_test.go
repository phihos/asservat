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
	if kinds := historyActionKinds(artifact.ContextExpectation{Processes: &artifact.ProcessCapture{}}); len(kinds) != 1 || kinds[0] != "processSnapshot" {
		t.Fatal("saved process capture lost its action kind", kinds)
	}
}
