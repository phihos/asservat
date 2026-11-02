package httpheaders

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// RecordingPage applies exactly the stored recording's limits and output
// cap: other limits or a non-httpHeaders recording yield no record.
func TestRecordingPageUsesTheRecordingsAcceptedLimits(t *testing.T) {
	_, b := pageProjection(t, 5)
	l := DefaultLimits()
	r := &artifact.Recording{Profile: "httpHeaders", MaxBytes: int64(len(b)), HTTP: &artifact.RecordingHTTP{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleMillis: int64(l.IdleTimeout / time.Millisecond)}}
	if got, max := RecordingLimits(r); got != l || max != int64(len(b)) {
		t.Fatalf("limits %+v %d", got, max)
	}
	p, err := RecordingPage{}.HTTPHeaderPage(b, r, selection(t, "", 2))
	if err != nil || p.Total != 5 || len(p.Records) != 2 {
		t.Fatalf("page: %v %+v", err, p)
	}
	for name, mutate := range map[string]func(*artifact.Recording){
		"raw-profile":  func(r *artifact.Recording) { r.Profile = "rawPackets" },
		"other-limits": func(r *artifact.Recording) { r.HTTP.MaxFlows-- },
		"smaller-cap":  func(r *artifact.Recording) { r.MaxBytes = int64(len(b)) - 1 },
		"missing-http": func(r *artifact.Recording) { r.HTTP = nil },
	} {
		c := *r
		h := *r.HTTP
		c.HTTP = &h
		mutate(&c)
		if _, err := (RecordingPage{}).HTTPHeaderPage(b, &c, selection(t, "", 2)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := (RecordingPage{}).HTTPHeaderPage(b, nil, selection(t, "", 2)); err == nil {
		t.Fatal("nil recording accepted")
	}
}
