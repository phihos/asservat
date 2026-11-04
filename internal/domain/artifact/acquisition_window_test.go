package artifact

import (
	"testing"
	"time"
)

func TestProfileAcquisitionWindowCanonicalDisplayMetadata(t *testing.T) {
	start := time.Date(2026, 11, 4, 9, 0, 0, 123456000, time.UTC)
	w := AcquisitionWindow{StartedAt: start, CompletedAt: start.Add(time.Second)}
	if !w.Valid() {
		t.Fatal("valid microsecond window rejected")
	}
	for _, mode := range []string{"missing-start", "missing-end", "reversed", "offset", "nanoseconds"} {
		t.Run(mode, func(t *testing.T) {
			bad := w
			switch mode {
			case "missing-start":
				bad.StartedAt = time.Time{}
			case "missing-end":
				bad.CompletedAt = time.Time{}
			case "reversed":
				bad.CompletedAt = start.Add(-time.Microsecond)
			case "offset":
				bad.StartedAt = start.In(time.FixedZone("source", 3600))
			case "nanoseconds":
				bad.CompletedAt = bad.CompletedAt.Add(time.Nanosecond)
			}
			if bad.Valid() {
				t.Fatal("noncanonical window accepted")
			}
		})
	}
	instant := w
	instant.CompletedAt = instant.StartedAt
	if !instant.Valid() {
		t.Fatal("microsecond normalization may collapse a short snapshot")
	}
	clone := w.Clone()
	clone.CompletedAt = start
	if w.CompletedAt.Equal(clone.CompletedAt) {
		t.Fatal("window clone aliases original")
	}
	var absent *AcquisitionWindow
	if absent.Clone() != nil {
		t.Fatal("unknown window invented")
	}
}

func TestProfileVerificationResultRequiresTimingOnlyForProfiles(t *testing.T) {
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	w := &AcquisitionWindow{StartedAt: now, CompletedAt: now.Add(time.Second)}
	for _, native := range []string{PprofArtifact, GoTraceArtifact} {
		e := ContextExpectation{NativeType: native, Profile: &GoProfileAcquisition{}, Registration: Registration{NativeLimit: 1024}}
		r := ContextVerificationResult{NativeBytes: 512, Acquisition: w}
		if !r.Valid(e) {
			t.Fatal("profile result rejected", native)
		}
		clone := r.Clone()
		clone.Acquisition.CompletedAt = now
		if clone.Acquisition.Equal(*r.Acquisition) {
			t.Fatal("result clone aliases window")
		}
		r.Acquisition = nil
		if r.Valid(e) {
			t.Fatal("new profile verification accepted unknown timing")
		}
	}
	e := ContextExpectation{Registration: Registration{NativeLimit: 1024}}
	if (ContextVerificationResult{NativeBytes: 512, Acquisition: w}).Valid(e) {
		t.Fatal("non-profile received profile timing")
	}
	for _, length := range []int64{-1, 1025} {
		if (ContextVerificationResult{NativeBytes: length}).Valid(e) {
			t.Fatal("invalid length accepted")
		}
	}
	if !(ContextVerificationResult{NativeBytes: 512}).Valid(e) {
		t.Fatal("legacy non-profile result changed")
	}
}
