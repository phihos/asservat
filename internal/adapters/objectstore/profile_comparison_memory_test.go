package objectstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/pprof/profile"
	"google.golang.org/protobuf/encoding/protowire"
)

type comparisonProbeInput struct {
	Side                     string            `json:"side"`
	Functions                int               `json:"functions"`
	Locations                int               `json:"locations"`
	Samples                  int               `json:"samples"`
	FrameVisits              int               `json:"frame_visits"`
	SampleLocationReferences int               `json:"sample_location_references"`
	InlineLines              int               `json:"inline_lines"`
	ValuesPerSample          int               `json:"values_per_sample"`
	SampleTypes              int               `json:"sample_types,omitempty"`
	LabelRecords             int               `json:"numeric_label_records_with_units,omitempty"`
	StringTableEntries       int               `json:"string_table_entries,omitempty"`
	SharedObjectUnits        int               `json:"shared_object_units,omitempty"`
	ProtobufBytes            int64             `json:"protobuf_bytes"`
	NativeBytes              int64             `json:"native_bytes"`
	ProtobufSHA256           string            `json:"protobuf_sha256"`
	NativeSHA256             string            `json:"native_sha256"`
	Files                    map[string]string `json:"encrypted_fixture_sha256"`
}

type comparisonProbeFixture struct {
	BinarySHA256 string                 `json:"binary_sha256"`
	Inputs       []comparisonProbeInput `json:"inputs"`
}

type comparisonProbeReport struct {
	Mode             string                 `json:"mode"`
	BinarySHA256     string                 `json:"binary_sha256"`
	GeneratorSHA256  string                 `json:"generator_binary_sha256"`
	GoVersion        string                 `json:"go_version"`
	Inputs           []comparisonProbeInput `json:"inputs"`
	GOMAXPROCS       int                    `json:"gomaxprocs"`
	GOGC             string                 `json:"gogc"`
	GOMEMLIMIT       string                 `json:"gomemlimit"`
	ElapsedNanos     int64                  `json:"operation_elapsed_ns"`
	UserCPUNanos     int64                  `json:"operation_user_cpu_ns"`
	SystemCPUNanos   int64                  `json:"operation_system_cpu_ns"`
	PeakRSSKiB       int64                  `json:"process_peak_rss_kib"`
	HeapInuse        uint64                 `json:"heap_inuse_after_operation"`
	SyntheticUnwraps int                    `json:"synthetic_unwraps"`
	SourcesClosed    [2]bool                `json:"sources_closed"`
	ResultValid      bool                   `json:"result_valid"`
	ResultRows       int                    `json:"result_rows"`
	Canceled         bool                   `json:"canceled"`
	CancelJoinNanos  int64                  `json:"cancel_join_ns"`
	Within256MiB     bool                   `json:"observed_rss_within_256mib"`
	Scope            string                 `json:"scope"`
}

// Explicit process modes reuse the real framed/manifest/TLS fixture. Run the
// producer in a separate process before either consumer: no graph construction,
// native input buffering or encryption allocation belongs to the measurement.
// Synthetic local providers share the consumer process, so their allocations
// are included. RSS is an observation, not cgroup containment or qualification.
func TestProfileComparisonEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_PROFILE_COMPARISON_GENERATE"); dir != "" {
		comparisonProbeGenerate(t, dir)
		return
	}
	dir := os.Getenv("ASSERVAT_PROFILE_COMPARISON_FIXTURE")
	if dir == "" {
		t.Skip("explicit two-input encrypted-process component measurement")
	}
	mode := os.Getenv("ASSERVAT_PROFILE_COMPARISON_MODE")
	if mode != "complete" && mode != "cancel-second-source" {
		t.Fatal("explicit complete or cancel-second-source mode required")
	}
	var fixture comparisonProbeFixture
	comparisonProbeLoad(t, filepath.Join(dir, "probe.json"), &fixture)
	if len(fixture.Inputs) != 2 {
		t.Fatal("expected an exact prepared pair")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	var sources [2]profileEncryptedFixture
	for index, side := range []string{"baseline", "incident"} {
		comparisonProbeLoad(t, filepath.Join(dir, side, "fixture.json"), &sources[index])
	}
	ctx, cancel := context.WithTimeout(t.Context(), identity.EvidenceReadRequestWindow)
	defer cancel()
	var before syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	var opened [2]*FramedNativeSource
	var keys [2]*projectionTestOpener
	var entered <-chan struct{}
	var unblock func()
	for index, side := range []string{"baseline", "incident"} {
		verifier, opener, blocked, release := profileEncryptedVerifier(t, filepath.Join(dir, side), sources[index], index == 1 && mode == "cancel-second-source")
		keys[index] = opener
		until, _ := ctx.Deadline()
		opened[index], err = verifier.OpenNative(ctx, sources[index].Source.Expectation, sources[index].Source.Copies, until)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(opened[index].Close)
		nativeSum := opened[index].Metadata().SHA256
		if hex.EncodeToString(nativeSum[:]) != fixture.Inputs[index].NativeSHA256 {
			t.Fatal("authenticated source does not match prepared native digest")
		}
		if index == 1 {
			entered, unblock = blocked, release
		}
	}
	defer unblock()
	selection := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: "perSecond", TopN: 20}
	type comparisonOutcome struct {
		value query.ProfileComparison
		err   error
	}
	done := make(chan comparisonOutcome, 1)
	go func() {
		value, err := evidence.ReadProfileComparison(ctx,
			evidence.ProfileComparisonSource{Opened: opened[0], Source: sources[0].Source, Scope: sources[0].Scope},
			evidence.ProfileComparisonSource{Opened: opened[1], Source: sources[1].Source, Scope: sources[1].Scope},
			selection, diagnostics.ComparePprof)
		done <- comparisonOutcome{value, err}
	}()
	var cancelAt time.Time
	if mode == "cancel-second-source" {
		select {
		case <-entered:
			cancelAt = time.Now()
			cancel()
			unblock()
		case <-ctx.Done():
			t.Fatal("comparison did not reach the second source", ctx.Err())
		}
	}
	var outcome comparisonOutcome
	select {
	case outcome = <-done:
	case <-ctx.Done():
		unblock()
		select {
		case outcome = <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("comparison failed to join its original deadline/cancellation")
		}
	}
	joinedAt := time.Now()
	elapsed := joinedAt.Sub(started)
	var after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	report := comparisonProbeReport{Mode: mode, BinarySHA256: binarySHA, GeneratorSHA256: fixture.BinarySHA256, GoVersion: runtime.Version(), Inputs: fixture.Inputs,
		GOMAXPROCS: runtime.GOMAXPROCS(0), GOGC: os.Getenv("GOGC"), GOMEMLIMIT: os.Getenv("GOMEMLIMIT"),
		ElapsedNanos: elapsed.Nanoseconds(), UserCPUNanos: comparisonProbeCPU(after.Utime) - comparisonProbeCPU(before.Utime), SystemCPUNanos: comparisonProbeCPU(after.Stime) - comparisonProbeCPU(before.Stime),
		PeakRSSKiB: after.Maxrss, HeapInuse: memory.HeapInuse, SyntheticUnwraps: keys[0].calls + keys[1].calls,
		ResultValid: outcome.err == nil && outcome.value.Valid(selection), ResultRows: len(outcome.value.Rows), Canceled: !cancelAt.IsZero(),
		Within256MiB: after.Maxrss <= (256 << 10), Scope: "Fresh uncontained consumer process; actual local framing, manifest authentication and pinned loopback TLS; two synthetic providers/receipts/authority; six synthetic unwraps. Provider allocations included. No SQL, real KMS, cgroup, deployed worker or installed qualification."}
	if !cancelAt.IsZero() {
		report.CancelJoinNanos = joinedAt.Sub(cancelAt).Nanoseconds()
	}
	for index, source := range opened {
		source.mu.Lock()
		report.SourcesClosed[index] = source.closed && source.reader == nil && source.cursor == nil && !source.busy && len(source.carry) == 0
		source.mu.Unlock()
	}
	if path := os.Getenv("ASSERVAT_PROFILE_COMPARISON_REPORT"); path != "" {
		comparisonProbeWrite(t, path, report)
	}
	t.Logf("two-source encrypted comparison: mode=%s elapsed=%s user=%s sys=%s peakRSSKiB=%d unwraps=%d closed=%v resultValid=%t", mode, elapsed, time.Duration(report.UserCPUNanos), time.Duration(report.SystemCPUNanos), report.PeakRSSKiB, report.SyntheticUnwraps, report.SourcesClosed, report.ResultValid)
	if report.SyntheticUnwraps != 6 || !report.SourcesClosed[0] || !report.SourcesClosed[1] {
		t.Fatal("unqualified unwrap or source cleanup result")
	}
	if mode == "complete" && (!report.ResultValid || report.ResultRows != 20) || mode == "cancel-second-source" && (outcome.err == nil || len(outcome.value.Rows) != 0 || ctx.Err() == nil) {
		t.Fatal("comparison result/cancellation", outcome.err)
	}
}

func comparisonProbeGenerate(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	fixture := comparisonProbeFixture{BinarySHA256: binarySHA}
	heavy := os.Getenv("ASSERVAT_PROFILE_COMPARISON_HEAVY") == "1"
	for index, side := range []string{"baseline", "incident"} {
		input := comparisonProbeNative(t, dir, side, uint64(index+1), heavy)
		native, err := os.Open(filepath.Join(dir, side+".pb.gz"))
		if err != nil {
			t.Fatal(err)
		}
		prepareProfileEncryptedFixture(t, filepath.Join(dir, side), native, false)
		if err := native.Close(); err != nil {
			t.Fatal(err)
		}
		input.Files = map[string]string{}
		for _, name := range []string{"data", "index", "manifest", "commit", "fixture.json"} {
			digest, _ := comparisonProbeDigest(t, filepath.Join(dir, side, name))
			input.Files[name] = digest
		}
		fixture.Inputs = append(fixture.Inputs, input)
	}
	comparisonProbeWrite(t, filepath.Join(dir, "probe.json"), fixture)
}

func comparisonProbeNative(t *testing.T, dir, side string, seed uint64, heavy bool) comparisonProbeInput {
	t.Helper()
	const n = diagnostics.MaxSummaryFunctions
	for _, limit := range []int{diagnostics.MaxSummaryLocations, diagnostics.MaxSummarySamples} {
		if n != limit {
			t.Fatal("probe shape requires reviewed table-cap alignment")
		}
	}
	if diagnostics.MaxSummaryFrameVisits != diagnostics.MaxPprofLocationReferences {
		t.Fatal("probe shape requires reviewed cap alignment")
	}
	random := rand.New(rand.NewPCG(seed, seed+100))
	p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"}, Period: 10000000, DurationNanos: int64(time.Second)}
	if heavy {
		for index := 1; index < 16; index++ {
			p.SampleType = append(p.SampleType, &profile.ValueType{Type: fmt.Sprintf("counter-%02d", index), Unit: "count"})
		}
	}
	for index := range n {
		suffix := make([]byte, 48)
		comparisonProbeRandomText(suffix, random)
		function := &profile.Function{ID: uint64(index + 1), Name: fmt.Sprintf("synthetic.%s.%06d.%s", side, index, suffix)}
		location := &profile.Location{ID: uint64(index + 1), Line: []profile.Line{{Function: function}}}
		p.Function = append(p.Function, function)
		p.Location = append(p.Location, location)
	}
	visits, labels := 0, 0
	for index := range n {
		count := diagnostics.MaxSummaryFrameVisits / n
		if index < diagnostics.MaxSummaryFrameVisits%n {
			count++
		}
		locations := []*profile.Location{p.Location[index]}
		for len(locations) < count {
			locations = append(locations, p.Location[random.IntN(n)])
		}
		visits += len(locations)
		sample := &profile.Sample{Location: locations, Value: make([]int64, len(p.SampleType))}
		sample.Value[0] = int64(seed*4 + 3)
		for index := 1; index < len(sample.Value); index++ {
			sample.Value[index] = int64(index)
		}
		if heavy && index < 32768 {
			sample.NumLabel = map[string][]int64{"bytes": {int64(random.Uint64() >> 1)}}
			sample.NumUnit = map[string][]string{"bytes": {"bytes"}}
			labels++
		}
		p.Sample = append(p.Sample, sample)
	}
	var plain bytes.Buffer
	if err := p.WriteUncompressed(&plain); err != nil {
		t.Fatal(err)
	}
	paddingBytes := artifact.MaxPprofDecompressedBytes - plain.Len() - 64
	if paddingBytes < 0 {
		comparisonProbeWrite(t, filepath.Join(dir, "unsupported-shape.json"), map[string]any{"side": side, "heavy": heavy, "functions": len(p.Function), "locations": len(p.Location), "samples": len(p.Sample), "frame_visits": visits, "values_per_sample": len(p.SampleType), "numeric_labels_with_units": labels, "protobuf_bytes_before_padding": plain.Len(), "protobuf_limit": artifact.MaxPprofDecompressedBytes})
		t.Fatal("maximum-table fixture already exceeds supported protobuf bound", plain.Len())
	}
	padding := make([]byte, paddingBytes)
	comparisonProbeRandomText(padding, random)
	p.Comments = []string{string(padding)}
	plain.Reset()
	if err := p.WriteUncompressed(&plain); err != nil {
		t.Fatal(err)
	}
	if plain.Len() > artifact.MaxPprofDecompressedBytes || artifact.MaxPprofDecompressedBytes-plain.Len() > 128 || visits != diagnostics.MaxSummaryFrameVisits {
		t.Fatal("unsupported or nonmaximum fixture", plain.Len(), visits)
	}
	file, err := os.OpenFile(filepath.Join(dir, side+".pb.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	if _, err := gz.Write(plain.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	verified, err := os.Open(filepath.Join(dir, side+".pb.gz"))
	if err != nil {
		t.Fatal(err)
	}
	acceptErr := diagnostics.CheckPprof(verified)
	closeErr := verified.Close()
	if acceptErr != nil || closeErr != nil {
		comparisonProbeWrite(t, filepath.Join(dir, "unsupported-shape.json"), map[string]any{"side": side, "heavy": heavy, "functions": len(p.Function), "locations": len(p.Location), "samples": len(p.Sample), "frame_visits": visits, "values_per_sample": len(p.SampleType), "numeric_labels_with_units": labels, "protobuf_bytes": plain.Len(), "verdict": fmt.Sprint(acceptErr), "close_error": fmt.Sprint(closeErr)})
		t.Fatal("native shape was not accepted by the unchanged publisher parser", acceptErr, closeErr)
	}
	protobufSum := sha256.Sum256(plain.Bytes())
	nativeSum, nativeBytes := comparisonProbeDigest(t, filepath.Join(dir, side+".pb.gz"))
	if nativeBytes <= artifact.FrameBytes || nativeBytes > artifact.MaxPprofBytes {
		t.Fatal("probe must cross an encrypted frame within native bounds", nativeBytes)
	}
	return comparisonProbeInput{Side: side, Functions: len(p.Function), Locations: len(p.Location), Samples: len(p.Sample), FrameVisits: visits, SampleLocationReferences: visits, InlineLines: len(p.Location), ValuesPerSample: len(p.SampleType), SampleTypes: len(p.SampleType), LabelRecords: labels, StringTableEntries: comparisonProbeStrings(t, plain.Bytes()), SharedObjectUnits: 2*len(p.Sample) + len(p.Function) + len(p.Location) + 8*labels, ProtobufBytes: int64(plain.Len()), NativeBytes: nativeBytes, ProtobufSHA256: hex.EncodeToString(protobufSum[:]), NativeSHA256: nativeSum}
}

// Count the writer's actual string-table records for fixture provenance only.
// The unchanged bounded native parser supplies the consumer's acceptance check.
func comparisonProbeStrings(t *testing.T, data []byte) int {
	t.Helper()
	count := 0
	for len(data) != 0 {
		field, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			t.Fatal("invalid generated protobuf tag")
		}
		data = data[n:]
		n = protowire.ConsumeFieldValue(field, typ, data)
		if n < 0 {
			t.Fatal("invalid generated protobuf field")
		}
		if field == 6 {
			count++
		}
		data = data[n:]
	}
	return count
}

func comparisonProbeRandomText(buffer []byte, random *rand.Rand) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	for index := range buffer {
		buffer[index] = alphabet[random.Uint64()&63]
	}
}

func comparisonProbeDigest(t *testing.T, path string) (string, int64) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, file)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil)), n
}

func comparisonProbeCPU(value syscall.Timeval) int64 {
	return value.Sec*int64(time.Second) + value.Usec*int64(time.Microsecond)
}

func comparisonProbeLoad(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, value) != nil {
		t.Fatal("invalid prepared fixture", path, err)
	}
}

func comparisonProbeWrite(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
