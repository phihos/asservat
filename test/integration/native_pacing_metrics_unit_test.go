package integration

import "testing"

func TestNativePacingProviderDeltaRejectsMissingOrResetCounters(t *testing.T) {
	before, after := map[string]nativeProviderCounters{}, map[string]nativeProviderCounters{}
	for _, name := range nativeProviderCategories {
		before[name] = nativeProviderCounters{}
		after[name] = nativeProviderCounters{}
	}
	before["s3_get"] = nativeProviderCounters{Dispatches: 2, Active: 1, Status2xx: 1, HeaderNanoseconds: 10}
	after["s3_get"] = nativeProviderCounters{Dispatches: 3, Active: 0, Status2xx: 3, HeaderNanoseconds: 30}
	d, err := nativeProviderDelta(before, after)
	if err != nil || d["s3_get"].Dispatches != 1 || d["s3_get"].Active != -1 || d["s3_get"].HeaderNanoseconds != 20 {
		t.Fatal("in-flight gauge decrease discarded valid monotonic work", err, d)
	}
	after["s3_get"] = nativeProviderCounters{Dispatches: 1}
	if _, err := nativeProviderDelta(before, after); err == nil {
		t.Fatal("counter reset reported as a valid cost delta")
	}
	delete(after, "kms_other")
	if _, err := nativeProviderDelta(before, after); err == nil {
		t.Fatal("missing counter category reported as zero")
	}
}
