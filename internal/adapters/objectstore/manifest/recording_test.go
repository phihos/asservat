package manifest

import (
	"bytes"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// ADR-248: a manual recording's manifest (API class, no ongoing save
// provenance, the accepted recording in the expectation) round-trips.
func TestManualRecordingManifest(t *testing.T) {
	v, e, l, c, _ := fixture(t)
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType = artifact.PCAPNGArtifact
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 2000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSnaplen}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	l.Binding = e.Binding()
	started := e.TriggeredAt.Add(time.Second)
	b, err := v.MarshalContext(e, l, c, started, started.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ParseContext(b, e, c); err != nil {
		t.Fatal(err)
	}
}

// ADR-279: a raw packet recording's manifest is the raw PCAPNG format of
// class raw; the same document claiming metadata is refused.
func TestManualRawRecordingManifest(t *testing.T) {
	v, e, l, c, _ := fixture(t)
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "raw"
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "rawPackets", Composition: []byte("{}"), DurationMillis: 2000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: 96,
		Filter: &artifact.RecordingFilter{Expression: "tcp port 8080", Program: []artifact.FilterInstruction{{Code: 6, K: 65535}}}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	l.Binding = e.Binding()
	started := e.TriggeredAt.Add(time.Second)
	b, err := v.MarshalContext(e, l, c, started, started.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ParseContext(b, e, c); err != nil {
		t.Fatal(err)
	}
	if err := validate(v.manifest, bytes.Replace(b, []byte(`"dataClass":"raw"`), []byte(`"dataClass":"metadata"`), 1), artifact.MaxRootBytes); err == nil {
		t.Fatal("raw PCAPNG manifest accepted as metadata")
	}
}
