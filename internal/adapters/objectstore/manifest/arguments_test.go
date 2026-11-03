package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func argumentNativeFixture(t *testing.T) (*Validator, artifact.ContextExpectation, ContextManifest, [][]byte) {
	t.Helper()
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	defs, _ := syscalls.ArgumentDefinitions([]string{"write"}, true, 128)
	digest := syscalls.ArgumentDefinitionDigest(defs)
	rule := collector.ArgumentObservationAccountingRule()
	var program artifact.Digest
	b, _ := hex.DecodeString(gadget.ArgumentObjectSHA256)
	copy(program[:], b)
	e := artifact.ContextExpectation{PodUID: testID(1), Recording: &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: 8 << 20, Syscalls: &artifact.RecordingSyscalls{Names: []string{"write"}, MaxEvents: 10, MaxEventsPerSecond: 100, MaxTrackedThreads: 16}, Arguments: &artifact.RecordingArguments{ProgramDigest: program, DefinitionDigest: artifact.Digest(digest), AccountingRule: artifact.Digest(rule), MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1 << 20, CaptureBuffers: true}}}
	m := ContextManifest{StartedAt: now, CompletedAt: now.Add(time.Second)}
	h := syscalls.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: e.PodUID, NodeUID: testID(2), BootID: testID(3), SourceEpoch: testID(4), CollectorPodUID: testID(5), SessionID: testID(6), Fence: testID(7), EngineDigest: gadget.ArgumentObjectSHA256, DefinitionDigest: hex.EncodeToString(digest[:]), AccountingRule: hex.EncodeToString(rule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: now}
	// Construct through the production encoder; no fixture-only native format.
	enter := syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Type: syscalls.EventEnter, PID: 10, TID: 11, Number: 1, Boot: 1, TaskStart: 1, ProcessStart: 1, ScalarMask: 5, Scalar: [6]uint64{3, 0, 2}}, Memory: &syscalls.ArgumentRecord{Data: []byte{0xff, 0}}}
	exit := syscalls.ArgumentProbe{Event: syscalls.ArgumentRecord{Type: syscalls.EventExit, PID: 10, TID: 11, Number: 1, Boot: 2, TaskStart: 1, ProcessStart: 1, Ret: 2}}
	ev, err := syscalls.ArgumentEvent(syscalls.ArgumentCall{Entry: &enter, Exit: &exit}, h, now, defs)
	if err != nil {
		t.Fatal(err)
	}
	f := syscalls.ArgumentFooter{Record: "footer", EndedAt: m.CompletedAt, Outcome: "completed", Retained: 1, CoverageUnknown: true}
	var lines [][]byte
	for _, line := range []any{h, syscalls.ArgumentEventLine{Record: "event", Event: ev}, f} {
		b, err := syscalls.AppendArgumentLine(nil, line)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, b)
	}
	return v, e, m, lines
}
func TestArgumentNativeStreamExactBytesQuietAndRefusals(t *testing.T) {
	v, e, m, lines := argumentNativeFixture(t)
	validate := func(raw []byte) error {
		c, err := newArgumentsCheck(v, e, m)
		source := artifact.ArgumentSourceProvenance{PodUID: e.PodUID, NodeUID: testID(2), BootID: testID(3), CollectorEpoch: testID(4), CollectorPodUID: testID(5), SessionID: testID(6), Fence: testID(7), StartedAt: m.StartedAt, StartBy: m.StartedAt.Add(time.Second / 2), Until: m.CompletedAt}
		semantic, checkErr := syscalls.NewArgumentCheck(e, source)
		if checkErr != nil {
			return checkErr
		}
		if err != nil {
			return err
		}
		for len(raw) > 0 {
			n := min(7, len(raw))
			if err = semantic.Write(raw[:n]); err != nil {
				return err
			}
			if err = c.Write(raw[:n]); err != nil {
				return err
			}
			raw = raw[n:]
		}
		if err := semantic.Close(); err != nil {
			return err
		}
		return c.Close()
	}
	good := bytes.Join(lines, nil)
	if err := validate(good); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(good, []byte(`base64:/wA=`)) {
		t.Fatal("binary value changed")
	}
	quietFooter := bytes.ReplaceAll(lines[2], []byte(`"retained":1`), []byte(`"retained":0`))
	if err := validate(bytes.Join([][]byte{lines[0], quietFooter}, nil)); err != nil {
		t.Fatal("quiet interval", err)
	}
	for name, raw := range map[string][]byte{
		"replaced source": bytes.ReplaceAll(good, []byte(testID(4)), []byte(testID(8))),
		"reordered":       bytes.Join([][]byte{lines[1], lines[0], lines[2]}, nil), "extra footer": append(append([]byte(nil), good...), lines[2]...), "missing footer": bytes.Join(lines[:2], nil), "no final newline": good[:len(good)-1], "wrong pin": bytes.ReplaceAll(good, []byte(gadget.ArgumentObjectSHA256), []byte(strings.Repeat("a", 64))), "bad base64": bytes.ReplaceAll(good, []byte("base64:/wA="), []byte("base64:???")), "too many events": bytes.Join([][]byte{lines[0], bytes.Repeat(lines[1], 11), lines[2]}, nil), "invented complete loss": bytes.ReplaceAll(good, []byte(`"coverage_unknown":true`), []byte(`"coverage_unknown":false`)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(raw); err == nil {
				t.Fatal("accepted invalid native")
			}
		})
	}
	// The metadata projection schema rejects the header and raw event shape.
	var rawEvent map[string]any
	if json.Unmarshal(lines[1], &rawEvent) != nil {
		t.Fatal("fixture")
	}
	if v.syscallEvent.Validate(rawEvent["event"]) == nil {
		t.Fatal("raw event accepted as metadata")
	}
}

func TestArgumentManifestIsRawAndRetainsTypedNativeFormat(t *testing.T) {
	v, e, layout, copies, _ := fixture(t)
	_, args, _, _ := argumentNativeFixture(t)
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass, e.ActionID = artifact.SyscallArgumentsArtifact, "raw", "a0123456789abcdef01234567"
	e.Recording = args.Recording
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.PodUID = args.PodUID
	layout.Binding = e.Binding()
	if err := e.Validate(); err != nil {
		t.Fatal("expectation", err)
	}
	native, err := v.MarshalContext(e, layout, copies, e.TriggeredAt, e.TriggeredAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(native, []byte(artifact.SyscallArgumentsFormat)) {
		t.Fatal("wrong native format")
	}
	if _, err = v.ParseContext(native, e, copies); err != nil {
		t.Fatal(err)
	}
	e.DataClass = "metadata"
	if e.Validate() == nil {
		t.Fatal("raw evidence downgraded")
	}
}
