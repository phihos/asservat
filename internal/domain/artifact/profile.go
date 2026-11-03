package artifact

import "time"

// GoProfileAcquisition is the accepted request of one Go endpoint profile
// (ADR-284): the facts the manifest records about acquisition. Semantic facts
// (sample types, period, mappings) come from the publisher's verification of
// the native bytes, never from the producer. It confers no authority.
type GoProfileAcquisition struct {
	SourceRef      string // administrator profile or recipe endpoint binding
	EndpointDigest Digest // resolved template, endpoint, audience and parameters
	Type, Mode     string
	DurationMillis int64 // zero for a snapshot or cumulative read
	ForceGC        bool
	// Admission inputs are absent on historical component-only artifacts.
	TimeoutMillis int64  `json:",omitempty"`
	MaxBytes      int64  `json:",omitempty"`
	Composition   []byte `json:",omitempty"`
}

// Valid checks the request against the Go pprof HTTP subset.
func (p *GoProfileAcquisition) Valid() bool {
	return p != nil && len(p.SourceRef) >= 1 && len(p.SourceRef) <= 63 && p.EndpointDigest != (Digest{}) && p.DurationMillis%1000 == 0 &&
		ValidGoProfile(p.Type, p.Mode, time.Duration(p.DurationMillis)*time.Millisecond, p.ForceGC)
}

// NativeType is the registered type of the endpoint's response.
func (p *GoProfileAcquisition) NativeType() string {
	if p.Type == "runtimeTrace" {
		return GoTraceArtifact
	}
	return PprofArtifact
}

// MaxPprofDecompressedBytes bounds a pprof artifact's gunzipped protobuf
// (ADR-284): the producer refuses a gzip trailer declaring more, and the
// publisher stops decompressing beyond it. Larger profiles are refused,
// never truncated. Parsing a 16 MiB table-heavy profile peaked at about
// 200 MiB of live heap, within the publisher's 512 MiB limit (ADR-284).
const MaxPprofDecompressedBytes = 16 << 20

// GoTraceHeaderBytes is the length of an execution trace header.
const GoTraceHeaderBytes = 16

// GoTraceHeader reports a version 2 execution trace header,
// "go 1.NN trace\x00\x00\x00" with NN from 22 to 99 (Go 1.22 and later).
// Older version 1 traces are refused rather than converted; the publisher's
// reader decides which version 2 releases it supports.
func GoTraceHeader(b []byte) bool {
	return len(b) >= GoTraceHeaderBytes && string(b[:5]) == "go 1." && b[5] >= '2' && b[5] <= '9' && b[6] >= '0' && b[6] <= '9' &&
		(b[5] > '2' || b[6] >= '2') && string(b[7:GoTraceHeaderBytes]) == " trace\x00\x00\x00"
}

// ValidGoProfile is the finite net/http/pprof subset: the CPU profile and
// execution trace are timed intervals (at most 60 and 15 seconds); heap and
// goroutine are snapshots, the other types cumulative, each also readable as
// a delta of at most 60 seconds. Forced GC applies only to a heap snapshot,
// because the handler takes its delta path before the GC branch.
func ValidGoProfile(typ, mode string, d time.Duration, forceGC bool) bool {
	if forceGC && (typ != "heap" || mode != "snapshot") {
		return false
	}
	delta := mode == "delta" && d >= time.Second && d <= 60*time.Second && d%time.Second == 0
	switch typ {
	case "cpu", "runtimeTrace":
		limit := 60 * time.Second
		if typ == "runtimeTrace" {
			limit = 15 * time.Second
		}
		return mode == "interval" && d >= time.Second && d <= limit && d%time.Second == 0
	case "heap", "goroutine":
		return mode == "snapshot" && d == 0 || delta
	case "allocs", "block", "mutex", "threadcreate":
		return mode == "cumulative" && d == 0 || delta
	}
	return false
}
