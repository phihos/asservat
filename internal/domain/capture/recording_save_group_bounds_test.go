package capture

import (
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"testing"
	"time"
)

func TestGroupRequestBoundsRemainServerOnlyAndOriginal(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	b := GroupRequestBounds{StartedAt: now, Until: now.Add(15 * time.Second), Requester: identity.Principal{Issuer: "https://identity.test", Subject: "developer", ClientID: "console", Kind: identity.Human}}
	if !b.Valid(now.Add(3*time.Second)) || b.Valid(b.Until) {
		t.Fatal("original finite request interval changed")
	}
	for name, change := range map[string]func(*GroupRequestBounds){"overlong": func(x *GroupRequestBounds) { x.Until = x.Until.Add(time.Microsecond) }, "not-started": func(x *GroupRequestBounds) { x.StartedAt = now.Add(time.Second) }, "empty-requester": func(x *GroupRequestBounds) { x.Requester = identity.Principal{} }, "noncanonical": func(x *GroupRequestBounds) { x.Until = x.Until.Add(time.Nanosecond) }} {
		t.Run(name, func(t *testing.T) {
			x := b
			change(&x)
			if x.Valid(now) {
				t.Fatal("invalid request provenance accepted")
			}
		})
	}
	plain, _ := json.Marshal(RecordingSaveGroupAdmission{})
	owned, _ := json.Marshal(RecordingSaveGroupAdmission{RequestBounds: &b})
	if string(plain) != string(owned) {
		t.Fatal("transient bounds entered persisted/wire admission JSON")
	}
	var restored RecordingSaveGroupAdmission
	if err := json.Unmarshal([]byte(`{"RequestBounds":{"StartedAt":"2026-10-30T12:00:00Z","Until":"2026-10-30T12:00:15Z"}}`), &restored); err != nil || restored.RequestBounds != nil {
		t.Fatal("wire reconstructed server request authority", err)
	}
}
