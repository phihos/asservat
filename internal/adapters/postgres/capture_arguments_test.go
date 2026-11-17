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
