package execution

import (
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-279/282: a human's rawPackets or httpHeaders recording selects the
// finite observation companion; a human's header recording and a policy
// recording without a raw byte predicate do not.
func TestMeteredRecordingSelectsManualPayloadProfiles(t *testing.T) {
	filter := &artifact.RecordingFilter{Expression: "tcp port 8080", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}
	human := identity.Principal{Issuer: "https://id.invalid", Subject: "user"}
	policy := authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "policy")
	for _, c := range []struct {
		actor   identity.Principal
		profile string
		want    bool
	}{
		{human, "rawPackets", true},
		{human, "httpHeaders", true},
		{human, "networkHeaders", false},
		{policy, "httpHeaders", false},
	} {
		var w APIContextWork
		w.Actor = c.actor
		w.Accepted.Expectation.Recording = &artifact.Recording{Kind: "packetCapture", Profile: c.profile, Filter: filter}
		if meteredRecording(w) != c.want {
			t.Fatal(c.profile, c.actor, "metered", !c.want)
		}
	}
}
