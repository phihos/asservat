package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestRecordingNativeClassPreservesRawArguments(t *testing.T) {
	for _, tt := range []struct{ kind, profile, native, class string }{
		{"syscallTrace", "arguments", artifact.SyscallArgumentsArtifact, "raw"},
		{"syscallTrace", "metadata", artifact.SyscallRecordsArtifact, "metadata"},
		{"packetCapture", "rawPackets", artifact.RawPCAPNGArtifact, "raw"},
		{"packetCapture", "httpHeaders", artifact.HTTPHeadersArtifact, "extract"},
		{"packetCapture", "headers", artifact.PCAPNGArtifact, "metadata"},
	} {
		t.Run(tt.profile, func(t *testing.T) {
			native, class := recordingNativeClass(artifact.Recording{Kind: tt.kind, Profile: tt.profile})
			if native != tt.native || class != tt.class {
				t.Fatalf("got %s/%s, want %s/%s", native, class, tt.native, tt.class)
			}
		})
	}
}

func TestArgumentPublicationReadsOnlyHistoricalSession(t *testing.T) {
	grants, ok := publicRuntimeDutyGrants("context-verify")
	if !ok {
		t.Fatal("missing publisher verification credential")
	}
	found := false
	for _, g := range grants {
		if g.object != "policy_observation_session" {
			continue
		}
		if g.kind != "table" || g.column != "" || g.privilege != "SELECT" {
			t.Fatalf("publication gained session effect: %+v", g)
		}
		found = true
	}
	if !found {
		t.Fatal("publisher cannot independently read original argument provenance")
	}
}
