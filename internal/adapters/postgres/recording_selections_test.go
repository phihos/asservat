package postgres

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

func TestRecordingSelectionMaximumMetadataAndExactCodec(t *testing.T) {
	refs := make([]value.RecordingReference, value.MaxRecordingSelections)
	for n := range refs {
		refs[n] = value.RecordingReference{SourceID: fmt.Sprintf("10000000-0000-4000-8000-%012d", n), Fence: "10000000-0000-4000-8000-000000000001", PolicyUID: strings.Repeat("\"", 64), PodUID: strings.Repeat("\\", 64), ActionID: strings.Repeat("<", 63), BindingDigest: artifact.Digest{255}, ExecutionDigest: artifact.Digest{255}}
		if !refs[n].Valid() {
			t.Fatal("maximal valid reference rejected")
		}
	}
	raw, err := encodeRecordingReferences(refs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("100 maximally sized references: %d bytes, cap65536", len(raw))
	decoded, err := decodeRecordingReferences(raw)
	if err != nil || !slices.Equal(decoded, refs) {
		t.Fatal("exact bounded metadata roundtrip", err)
	}
	if _, err = decodeRecordingReferences(append(raw, 'x')); err == nil {
		t.Fatal("noncanonical trailing input accepted")
	}
}
