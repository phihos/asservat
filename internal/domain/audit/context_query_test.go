package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestContextQueryAuditNamesFormatsAndEffects(t *testing.T) {
	for _, name := range []string{"get_file_excerpt", "get_query_result"} {
		in := connectorAuditIntent()
		in.Name, in.InputFormat, in.Peer = name, "context-query-input/v1", nil
		in.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "reader", ClientID: "console", Kind: identity.Human}
		if OperationLane(name) != "normal" || !in.Valid() {
			t.Fatalf("query audit rejected: %s", name)
		}
		for _, effect := range []string{"none", "accepted", "unknown"} {
			out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: effect, ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
			if !out.Valid() {
				t.Fatalf("query effect rejected: %s %s", name, effect)
			}
		}
		for _, format := range []string{"context-input/v1", "invalid-input/v1", "native-content-input/v1"} {
			bad := in
			bad.InputFormat = format
			if bad.Valid() {
				t.Fatalf("query accepted unrelated format: %s", format)
			}
		}
		in.Name = "get_case"
		if in.Valid() {
			t.Fatal("metadata read accepted query format")
		}
	}
}
