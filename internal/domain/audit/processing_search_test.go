package audit

import (
	"testing"

	"asservat.local/asservat/internal/domain/identity"
)

func TestProcessingEvidenceSearchUsesNormalAuditAndContextInput(t *testing.T) {
	intent := connectorAuditIntent()
	intent.Name, intent.InputFormat, intent.Peer = "search_processing_evidence", "context-input/v1", nil
	intent.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "operator", ClientID: "console", Kind: identity.Human}
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
