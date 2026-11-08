package live

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	v "asservat.local/asservat/internal/domain/live"
)

func TestLiveOwnerPrivateResultPreservesRowsCursorAndOriginalCutoff(t *testing.T) {
	now := time.Now()
	rows := []v.Row{
		{ID: "packet", SourceID: uid, Sequence: 1, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Projection: v.Packet, PodUID: uid, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", Direction: "unknown"}},
		{ID: "http", SourceID: uid, Sequence: 2, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Projection: v.HTTP, PodUID: uid, HTTP: &v.HTTPFields{Method: "GET", Headers: []v.Header{{Name: "content-type", Value: "text/plain"}}, Pairing: "request"}},
		{ID: "syscall", SourceID: uid, Sequence: 3, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Projection: v.Syscall, PodUID: uid, Syscall: &v.SyscallFields{PID: 1, Name: "read"}},
	}
	want := CommandResult{Batch: &v.Batch{Rows: rows, Cursor: "original-bound-cursor", DisclosureUntil: now.Add(time.Second)}}
	raw, e := EncodeOwnerResult(want)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeOwnerResult(raw, now)
	if e != nil || got.Batch.Cursor != want.Batch.Cursor || len(got.Batch.Rows) != 3 || !got.Batch.DisclosureUntil.IsZero() {
		t.Fatal("private page", got, e)
	}
	for j, row := range got.Batch.Rows {
		if !row.Valid(now) || !bytes.Equal(mustOwnerJSON(t, row), mustOwnerJSON(t, rows[j])) {
			t.Fatal("typed row changed", j)
		}
	}
	// Private authority cannot be supplied in data JSON; it comes only from the
	// authenticated retained frame and is restored by the receiving forwarder.
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"cursor":`), []byte(`"DisclosureUntil":"2099-01-01T00:00:00Z","cursor":`), 1), bytes.Replace(raw, []byte(`"protocol":"TCP"`), []byte(`"protocol":"TCP","body":"user data"`), 1), bytes.Replace(raw, []byte(`"projection":"packetMetadata"`), []byte(`"projection":"httpHeaders"`), 1)} {
		if _, e := DecodeOwnerResult(bad, now); e == nil {
			t.Fatal("invalid private field union accepted")
		}
	}
}
func mustOwnerJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
