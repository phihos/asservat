package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestGrantMutationOutcomeEffectsAreClosed(t *testing.T) {
	for _, name := range []string{"decide_review", "revoke_grant", "request_policy_grant", "get_grant", "list_reviews", "invented_grant_mutation"} {
		in := connectorAuditIntent()
		in.Name, in.InputFormat, in.Peer = name, "context-input/v1", nil
		in.Actor = identity.Principal{Issuer: "https://identity.invalid", Subject: "reviewer", ClientID: "console", Kind: identity.Human}
		for _, effect := range []string{"none", "accepted", "unknown"} {
			out := OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: effect, ClientReceipt: "unknown", OutputDigest: artifact.Digest{4}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: in.CreatedAt.Add(time.Second)}
			want := name != "invented_grant_mutation" && (effect == "none" || name == "decide_review" || name == "revoke_grant" || name == "request_policy_grant")
			if out.Valid() != want {
				t.Errorf("%s effect %s valid=%v want=%v", name, effect, out.Valid(), want)
			}
		}
	}
}
