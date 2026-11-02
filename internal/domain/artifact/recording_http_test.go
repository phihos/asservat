package artifact

import (
	"encoding/json"
	"strings"
	"testing"
)

func httpRecording() Recording {
	return Recording{Kind: "packetCapture", Profile: "httpHeaders", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: MaxRawSnaplen, RequireApproval: true,
		Filter: &RecordingFilter{Expression: "tcp port 8080", Program: []FilterInstruction{{Code: 6, K: 65535}}},
		HTTP:   &RecordingHTTP{MaxFlows: MaxHTTPFlows, MaxHeaderBytes: MaxHTTPHeaderBytes, MaxFlowBytes: MaxHTTPFlowBytes, MaxTotalBytes: MaxHTTPTotalBytes, IdleMillis: MaxHTTPIdleMillis}}
}

// ADR-282: an httpHeaders recording is finite, filtered, at the fixed engine
// snaplen and within the specified parser maxima; other profiles cannot carry
// HTTP bounds, and the added field leaves other encodings unchanged.
func TestHTTPRecordingBounds(t *testing.T) {
	ok := httpRecording()
	if !ok.Valid() || !ok.Clone().Valid() {
		t.Fatal("valid HTTP recording refused")
	}
	clone := ok.Clone()
	clone.HTTP.MaxFlows = 1
	if ok.HTTP.MaxFlows != MaxHTTPFlows {
		t.Fatal("clone shares HTTP bounds")
	}
	for name, edit := range map[string]func(*Recording){
		"over 15 seconds":  func(r *Recording) { r.DurationMillis = 16_000 },
		"other snaplen":    func(r *Recording) { r.Snaplen = RecordingSnaplen },
		"no filter":        func(r *Recording) { r.Filter = nil },
		"no bounds":        func(r *Recording) { r.HTTP = nil },
		"too many flows":   func(r *Recording) { r.HTTP.MaxFlows = MaxHTTPFlows + 1 },
		"header block":     func(r *Recording) { r.HTTP.MaxHeaderBytes = MaxHTTPHeaderBytes + 1 },
		"per flow":         func(r *Recording) { r.HTTP.MaxFlowBytes = MaxHTTPFlowBytes + 1 },
		"total":            func(r *Recording) { r.HTTP.MaxTotalBytes = MaxHTTPTotalBytes + 1 },
		"total below flow": func(r *Recording) { r.HTTP.MaxTotalBytes = r.HTTP.MaxFlowBytes - 1 },
		"idle too long":    func(r *Recording) { r.HTTP.IdleMillis = MaxHTTPIdleMillis + 1 },
		"idle too short":   func(r *Recording) { r.HTTP.IdleMillis = 999 },
		"prefix caps":      func(r *Recording) { r.ProtocolSnaplen = &RecordingProtocolSnaplen{TCP: 100} },
		"raw with bounds":  func(r *Recording) { r.Profile = "rawPackets" },
		"header with bounds": func(r *Recording) {
			r.Profile, r.Snaplen = "networkHeaders", RecordingSnaplen
		},
	} {
		r := ok.Clone()
		edit(r)
		if r.Valid() {
			t.Fatal(name, "accepted")
		}
	}
	header := Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: RecordingSnaplen}
	b, _ := json.Marshal(header)
	if strings.Contains(string(b), "HTTP") {
		t.Fatal("header recording encoding changed", string(b))
	}
}

// ADR-282: the httpHeaders profile, the HTTP projection type and the extract
// class come together; extract is served only for that type.
func TestHTTPExpectationTiesProfileTypeAndClass(t *testing.T) {
	e := typedExpectation(t, HTTPHeadersArtifact, RecordingNativeLimit)
	r := httpRecording()
	e.Recording, e.DataClass = &r, "extract"
	if err := e.Validate(); err != nil || !e.ServedClass() {
		t.Fatal("HTTP projection expectation", err)
	}
	for name, change := range map[string]func(*ContextExpectation){
		"metadata class":  func(x *ContextExpectation) { x.DataClass = "metadata" },
		"raw class":       func(x *ContextExpectation) { x.DataClass = "raw" },
		"no recording":    func(x *ContextExpectation) { x.Recording = nil },
		"pcapng type":     func(x *ContextExpectation) { x.NativeType = PCAPNGArtifact },
		"raw pcapng type": func(x *ContextExpectation) { x.NativeType = RawPCAPNGArtifact },
		"header recording": func(x *ContextExpectation) {
			x.Recording.Profile, x.Recording.Snaplen, x.Recording.HTTP = "networkHeaders", RecordingSnaplen, nil
		},
	} {
		x := e
		x.Recording = e.Recording.Clone()
		change(&x)
		if x.Validate() == nil {
			t.Fatal("accepted:", name)
		}
	}
	pcap := typedExpectation(t, PCAPNGArtifact, StreamingNativeLimit)
	pcap.DataClass = "extract"
	if pcap.ServedClass() {
		t.Fatal("extract served for a packet capture")
	}
}
