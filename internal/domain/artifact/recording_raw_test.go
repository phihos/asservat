package artifact

import (
	"encoding/json"
	"strings"
	"testing"
)

// ADR-279: a raw recording is finite, approved, within the engine snaplen
// and its per-transport caps; header recordings cannot carry caps, and the
// added fields do not change existing recording encodings.
func TestRawRecordingBounds(t *testing.T) {
	ok := Recording{Kind: "packetCapture", Profile: "rawPackets", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: 96, RequireApproval: true,
		ProtocolSnaplen: &RecordingProtocolSnaplen{TCP: 200, UDP: 64}}
	if !ok.Valid() || !ok.Clone().Valid() {
		t.Fatal("valid raw recording refused")
	}
	clone := ok.Clone()
	clone.ProtocolSnaplen.TCP = 1
	if ok.ProtocolSnaplen.TCP != 200 {
		t.Fatal("clone shares caps")
	}
	for name, edit := range map[string]func(*Recording){
		"over 15 seconds":   func(r *Recording) { r.DurationMillis = 16_000 },
		"no approval":       func(r *Recording) { r.RequireApproval = false },
		"snaplen too large": func(r *Recording) { r.Snaplen = MaxRawSnaplen + 1 },
		"zero snaplen":      func(r *Recording) { r.Snaplen = 0 },
		"cap too large":     func(r *Recording) { r.ProtocolSnaplen.UDP = MaxRawSnaplen + 1 },
		"empty caps":        func(r *Recording) { r.ProtocolSnaplen = &RecordingProtocolSnaplen{} },
		"header with caps":  func(r *Recording) { r.Profile, r.Snaplen = "networkHeaders", RecordingSnaplen },
	} {
		r := ok.Clone()
		edit(r)
		if r.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	header := Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: RecordingSnaplen}
	b, _ := json.Marshal(header)
	if strings.Contains(string(b), "ProtocolSnaplen") {
		t.Fatal("header recording encoding changed", string(b))
	}
}
