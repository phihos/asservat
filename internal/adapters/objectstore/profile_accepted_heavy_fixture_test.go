package objectstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/domain/analysis"
)

// Explicit native-only build producer. This test binary runs before image
// construction, outside both the 64MiB workload and 384MiB acquisition worker.
// Passing it proves parser acceptance of these inputs, not worker containment.
func TestProfileAcceptedHeavyNativeFixture(t *testing.T) {
	dir := os.Getenv("ASSERVAT_PROFILE_ACCEPTED_HEAVY_DIR")
	if dir == "" {
		t.Skip("explicit separate-process accepted-heavy fixture producer")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	type input struct {
		Filename string `json:"filename"`
		comparisonProbeInput
	}
	manifest := struct {
		Format                string  `json:"format"`
		GeneratorBinarySHA256 string  `json:"generator_binary_sha256"`
		GoVersion             string  `json:"go_version"`
		ProfileType           string  `json:"profile_type"`
		SampleType            string  `json:"sample_type"`
		Unit                  string  `json:"unit"`
		DurationNS            int64   `json:"duration_ns"`
		Inputs                []input `json:"inputs"`
	}{Format: "accepted-heavy-pprof-fixture/v1", GeneratorBinarySHA256: binarySHA, GoVersion: runtime.Version(), ProfileType: "cpu", SampleType: "cpu", Unit: "nanoseconds", DurationNS: int64(10 * time.Second)}
	// The original side names and deterministic seeds preserve the reviewed
	// heavy shape; only its requested native duration differs from the old probe.
	for index, side := range []string{"baseline", "incident"} {
		shape := comparisonProbeNative(t, dir, side, uint64(index+1), true, 10*time.Second)
		if shape.Functions != 100000 || shape.Locations != 100000 || shape.Samples != 100000 || shape.FrameVisits != 1048576 || shape.ValuesPerSample != 16 || shape.SampleTypes != 16 || shape.LabelRecords != 32768 || shape.SharedObjectUnits != 662144 || shape.StringTableEntries != 100021 || shape.ProtobufBytes != (16<<20)-56 {
			t.Fatalf("accepted-heavy shape changed: %+v", shape)
		}
		// Read the serialized input through the real analyzer too: a constant
		// manifest duration must never hide accidentally retaining the old 1s
		// producer default or selecting a different native sample type/unit.
		native, err := os.Open(filepath.Join(dir, side+".pb.gz"))
		if err != nil {
			t.Fatal(err)
		}
		selection, err := analysis.NormalizeProfileSummarySelection("cpu", 1)
		if err != nil {
			t.Fatal(err)
		}
		summary, summaryErr := diagnostics.SummarizePprof(t.Context(), native, selection)
		closeErr := native.Close()
		if summaryErr != nil || closeErr != nil || !summary.Valid(selection) || summary.SampleType != "cpu" || summary.Unit != "nanoseconds" || summary.DurationSeconds == nil || *summary.DurationSeconds != 10 || summary.Total != int64((index+1)*4+3)*100000 {
			t.Fatalf("serialized profile semantics changed: summary=%+v error=%v close=%v", summary, summaryErr, closeErr)
		}
		name := "profile-heavy-" + side + ".pb.gz"
		// Link exclusively rather than overwrite an existing prepared input.
		if err := os.Link(filepath.Join(dir, side+".pb.gz"), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, side+".pb.gz")); err != nil {
			t.Fatal(err)
		}
		manifest.Inputs = append(manifest.Inputs, input{Filename: name, comparisonProbeInput: shape})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(data) > 16<<10 {
		t.Fatal("invalid bounded manifest", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "profile-heavy-manifest.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	t.Logf("accepted native pair: %s", data)
}
