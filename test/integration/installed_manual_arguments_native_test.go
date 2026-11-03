package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const manualArgumentsProfile = "argument-capture"
const manualArgumentsMarker = "synthetic-approved-recording"
const manualArgumentsRate = 1000
const manualArgumentsRetained = 10000

// The existing signal workload's /log handler writes this known synthetic
// marker to stdout with fmt.Fprintln. Its write syscall is in the qualified
// closed table; no exec, trial capture or additional workload is needed.
func manualArgumentsProfileDefinition() (map[string]any, error) {
	raw, err := os.ReadFile("../../internal/application/planning/profiles/syscall-activity-v1.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Definition map[string]any `json:"definition"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	doc.Definition["displayName"] = "Synthetic finite write arguments"
	doc.Definition["description"] = "Explicitly approved raw write arguments and bounded synthetic buffers."
	recipe := doc.Definition["recipe"].(map[string]any)
	recipe["description"] = doc.Definition["description"]
	recipe["maxTotalBytes"], recipe["maxDuration"] = artifact.RecordingNativeLimit, "45s"
	action := recipe["actions"].([]any)[0].(map[string]any)
	action["impact"], action["executionMode"] = "sensitiveRead", "onTrigger"
	action["limits"] = map[string]any{"maxBytes": artifact.RecordingNativeLimit, "timeout": "15s"}
	params := action["parameters"].(map[string]any)
	params["maxFrozenBytes"] = artifact.RecordingNativeLimit
	params["mode"], params["before"], params["after"] = "arguments", "0s", "5s"
	params["syscalls"] = map[string]any{"mode": "include", "names": []string{"write"}}
	params["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": true}
	params["maxEvents"], params["maxEventsPerSecond"], params["maxTrackedThreads"] = manualArgumentsRetained, manualArgumentsRate, 64
	doc.Definition["editableFields"] = append(doc.Definition["editableFields"].([]any), map[string]any{"actionID": "syscalls", "field": "syscallArguments", "label": "Argument reads"})
	return doc.Definition, nil
}

func manualArgumentsCaptureInput(cluster, namespace, workload string, stop bool) map[string]any {
	after, timeout, duration := "5s", "15s", "15s"
	if stop {
		after, timeout, duration = "30s", "40s", "45s"
	}
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{"id": "calls", "profileRef": map[string]string{"catalog": "namespace", "name": manualArgumentsProfile, "version": "v1"},
				"overrides": []any{map[string]any{"actionID": "syscalls", "field": "syscallAfter", "value": after}, map[string]any{"actionID": "syscalls", "field": "actionTimeout", "value": timeout}, map[string]any{"actionID": "syscalls", "field": "syscallArguments", "value": map[string]any{"maxBytesPerEvent": 128, "captureBuffers": !stop}}}}},
			"maxTotalBytes": artifact.RecordingNativeLimit, "maxDuration": duration,
		},
	}
}

// This fixture compiler uses the actual pinned mechanism and definition APIs,
// not invented ABI facts. It grants no collection authority.
type installedArgumentsCompiler struct{ recordingCompiler }

func (installedArgumentsCompiler) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	defs, err := syscalls.ArgumentDefinitions(names, buffers, int(maximum))
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	pin, err := hex.DecodeString(gadget.ArgumentObjectSHA256)
	if err != nil || len(pin) != 32 {
		return artifact.RecordingArguments{}, artifact.ErrInvalid
	}
	var program artifact.Digest
	copy(program[:], pin)
	return artifact.RecordingArguments{ProgramDigest: program, DefinitionDigest: artifact.Digest(syscalls.ArgumentDefinitionDigest(defs)), AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: int64(syscalls.ArgumentMaxProbeBytes(defs)), MaxBytesPerEvent: maximum, MaxBytesPerSecond: planvalue.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}, nil
}

type installedArgumentsSource struct {
	Source                                        artifact.ArgumentSourceProvenance
	Arguments                                     artifact.RecordingArguments
	ByteCredit, EventCredit, DurationMillis, Rate int64
}
type installedArgumentsSourceReader func(string) installedArgumentsSource

// The expected source comes from the original immutable SQL session, never
// from the downloaded header. This administrator read is fixture verification,
// not a production credential or a source of collection/disclosure authority.
func installedArgumentsSQLSource(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) installedArgumentsSourceReader {
	return func(captureID string) installedArgumentsSource {
		t.Helper()
		var rootID, id pgtype.UUID
		if rootID.Scan(root) != nil || id.Scan(captureID) != nil {
			t.Fatal("argument observation identity")
		}
		row, err := custodydb.New(admin).ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: rootID, CaptureID: id})
		if err != nil {
			t.Fatal("original argument session read", err)
		}
		out := installedArgumentsSource{Source: artifact.ArgumentSourceProvenance{PodUID: row.PodUid, NodeUID: row.NodeUid, BootID: row.BootID, CollectorPodUID: row.CollectorPodUid, CollectorEpoch: row.CollectorEpoch, SessionID: uuid.UUID(row.ID.Bytes).String(), Fence: uuid.UUID(row.Fence.Bytes).String(), StartedAt: row.StartedAt.Time, StartBy: row.StartBy.Time, Until: row.SessionUntil.Time}, ByteCredit: row.Credit, EventCredit: row.EventCredit, DurationMillis: row.DurationMillis, Rate: row.MaxEventsPerSecond}
		out.Arguments = artifact.RecordingArguments{MaxProbeBytes: row.MaxProbeBytes, MaxBytesPerEvent: row.MaxBytesPerEvent, MaxBytesPerSecond: row.MaxBytesPerSecond, CaptureBuffers: row.CaptureBuffers}
		if len(row.ProgramDigest) != 32 || len(row.ArgumentDefinitionDigest) != 32 || len(row.AccountingRule) != 32 {
			t.Fatal("argument session lacks immutable mechanism pins")
		}
		copy(out.Arguments.ProgramDigest[:], row.ProgramDigest)
		copy(out.Arguments.DefinitionDigest[:], row.ArgumentDefinitionDigest)
		copy(out.Arguments.AccountingRule[:], row.AccountingRule)
		if !out.Source.Valid() || !out.Arguments.Valid() || row.Sequence != 1 || row.MaxTrackedThreads != 64 {
			t.Fatal("invalid original argument session")
		}
		return out
	}
}

func checkManualArgumentsNative(native []byte, pod string, expected installedArgumentsSource) (artifact.ArgumentFooter, error) {
	var footer artifact.ArgumentFooter
	mechanism, err := (installedArgumentsCompiler{}).CompileArguments([]string{"write"}, true, 128)
	if err != nil || expected.Arguments != mechanism || expected.Source.PodUID != pod || expected.Rate != manualArgumentsRate || expected.DurationMillis != 5000 || expected.EventCredit != manualArgumentsRate*6 || expected.ByteCredit != 6*planvalue.SensitiveMaxBytesPerSecond {
		return footer, fmt.Errorf("original session differs from reviewed bounded write mechanism: %v", err)
	}
	e := artifact.ContextExpectation{PodUID: pod, Recording: &artifact.Recording{MaxBytes: artifact.RecordingNativeLimit, Arguments: &expected.Arguments, Syscalls: &artifact.RecordingSyscalls{Names: []string{"write"}, MaxEvents: manualArgumentsRetained}}}
	check, err := syscalls.NewArgumentCheck(e, expected.Source)
	if err != nil {
		return footer, err
	}
	if err = check.Write(native); err != nil {
		return footer, err
	}
	if err = check.Close(); err != nil {
		return footer, err
	}
	lines := bytes.Split(bytes.TrimSuffix(native, []byte{'\n'}), []byte{'\n'})
	if len(lines) < 3 {
		return footer, fmt.Errorf("no captured argument event")
	}
	if err = json.Unmarshal(lines[len(lines)-1], &footer); err != nil {
		return footer, err
	}
	if footer.Outcome != "completed" || footer.Retained != uint64(len(lines)-2) || footer.Retained == 0 || footer.OutputFull != 0 || footer.Malformed != 0 || footer.ObservedEvents == nil || footer.ObservedBytes == nil || *footer.ObservedEvents < footer.Retained || *footer.ObservedEvents > uint64(expected.EventCredit) || *footer.ObservedBytes > uint64(expected.ByteCredit) || (*footer.ObservedBytes < *footer.ObservedEvents*256 || *footer.ObservedBytes > *footer.ObservedEvents*uint64(mechanism.MaxProbeBytes) || *footer.ObservedBytes%256 != 0) || !footer.CoverageUnknown {
		return footer, fmt.Errorf("argument counters are missing or outside original credit: %+v", footer)
	}
	found := false
	for _, line := range lines[1 : len(lines)-1] {
		var event artifact.ArgumentEventLine
		if err = json.Unmarshal(line, &event); err != nil {
			return footer, err
		}
		if event.Event.Syscall != "write" {
			return footer, fmt.Errorf("unreviewed syscall")
		}
		for _, arg := range event.Event.Arguments {
			if strings.HasPrefix(arg.Value, "base64:") {
				raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(arg.Value, "base64:"))
				if err != nil || len(raw) > 128 {
					return footer, fmt.Errorf("invalid bounded buffer")
				}
				if event.Event.Outcome == "success" && bytes.Contains(raw, []byte(manualArgumentsMarker)) {
					found = true
				}
			}
		}
	}
	if !found {
		return footer, fmt.Errorf("no successful write of the synthetic workload marker")
	}
	return footer, nil
}

func qualifyManualArgumentsNative(t *testing.T, native []byte, captureID, pod string, source installedArgumentsSourceReader) {
	t.Helper()
	// The caller has already authenticated the download and verified size/hash.
	// Retain synthetic fixture bytes even if a later semantic assertion fails.
	if err := os.WriteFile("../results/manual-arguments.jsonl", native, 0600); err != nil {
		t.Fatal(err)
	}
	if source == nil {
		t.Fatal("missing independent original-session verifier")
	}
	original := source(captureID)
	footer, err := checkManualArgumentsNative(native, pod, original)
	if err != nil {
		t.Fatal("downloaded argument provenance/counters/payload", err)
	}
	t.Logf("manual arguments %s: authenticated native hash matched; %d bytes, %d retained writes, %d observed probes/%d charged bytes within original %d/%d credit; source matched immutable SQL session; coverage remains explicitly unknown", captureID, len(native), footer.Retained, *footer.ObservedEvents, *footer.ObservedBytes, original.EventCredit, original.ByteCredit)
}
