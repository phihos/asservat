package postgres

import (
	"bytes"
	"testing"

	"asservat.local/asservat/internal/domain/identity"
)

func TestRecordingGroupChildrenHaveSeparatePrivateRequestKeys(t *testing.T) {
	parent := "00000000-0000-4000-8000-000000000001"
	actor := identity.Principal{Issuer: "https://example.invalid", Subject: "requester", ClientID: "console", Kind: identity.Human}
	public := contextRequestKey(actor, "group-save-request")
	seen := map[string]bool{}
	for n := 0; n < 16; n++ {
		key := recordingGroupChildRequestKey(parent, n)
		if len(key) != 32 || bytes.Equal(key, public) || seen[string(key)] || !bytes.Equal(key, recordingGroupChildRequestKey(parent, n)) {
			t.Fatal("child aliases public request, sibling, or replay", n)
		}
		seen[string(key)] = true
	}
	if bytes.Equal(recordingGroupChildRequestKey(parent, 0), recordingGroupChildRequestKey("00000000-0000-4000-8000-000000000002", 0)) {
		t.Fatal("child key crossed parent")
	}
}
