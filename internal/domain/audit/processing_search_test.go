package audit

import (
	"testing"
)

func TestProcessingEvidenceSearchUsesNormalAuditAndContextInput(t *testing.T) {
	intent := humanAuditIntent("search_processing_evidence", "context-input/v1")
	if OperationLane(intent.Name) != "normal" || !intent.Valid() {
		t.Fatal("processing evidence search did not accept a normal context intent")
	}
	for _, format := range []string{"", "invalid-input/v1", "processing-input/v1", "context-query-input/v1"} {
		intent.InputFormat = format
		if intent.Valid() {
			t.Fatalf("processing evidence search accepted input format %q", format)
		}
	}
}
