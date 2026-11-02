package postgres

import (
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
)

// ADR-282: the query fence and the processing facet accept exactly the
// pod-status metadata context or an httpHeaders extract of one frame.
func TestProjectionSourcePinsAreExact(t *testing.T) {
	pod := analysis.ContextProjectionScope{}
	http := analysis.ContextProjectionScope{NativeType: artifact.HTTPHeadersArtifact}
	podStatus := artifact.ContextExpectation{DataClass: "metadata", Registration: artifact.Registration{NativeLimit: artifact.MaxContextBytes}}
	extract := artifact.ContextExpectation{NativeType: artifact.HTTPHeadersArtifact, DataClass: "extract", Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}}
	if !scopeSource(pod, podStatus) || !scopeSource(http, extract) || scopeSource(pod, extract) || scopeSource(http, podStatus) {
		t.Fatal("scope source did not pin the published type")
	}
	for name, e := range map[string]artifact.ContextExpectation{
		"raw-pod-status": {DataClass: "raw", Registration: podStatus.Registration},
		"pcapng":         {NativeType: artifact.PCAPNGArtifact, DataClass: "metadata", Registration: extract.Registration},
		"extract-limit":  {NativeType: artifact.HTTPHeadersArtifact, DataClass: "extract", Registration: artifact.Registration{NativeLimit: artifact.HTTPHeadersNativeLimit}},
		"extract-class":  {NativeType: artifact.HTTPHeadersArtifact, DataClass: "metadata", Registration: extract.Registration},
	} {
		if scopeSource(pod, e) || scopeSource(http, e) {
			t.Fatalf("%s accepted", name)
		}
	}
	record := func(nativeType, format, class, evidenceType string, limit int64, digest artifact.Digest) app.ContextProjectionEvidence {
		return app.ContextProjectionEvidence{NativeType: nativeType, SourceFormat: format, DataClass: class, SourceProjectionDigest: digest,
			Retained: privacy.RetainedArtifact{Registration: artifact.Registration{NativeLimit: limit}, Input: privacy.Input{EvidenceType: evidenceType}}}
	}
	if !projectionSource(record("", artifact.ContextFormat, "metadata", "context", artifact.MaxContextBytes, analysis.ContextSourceProjectionDigest())) ||
		!projectionSource(record(artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, "extract", "packetCapture", artifact.RecordingNativeLimit, artifact.Digest{})) {
		t.Fatal("refused a projection source")
	}
	for name, r := range map[string]app.ContextProjectionEvidence{
		"mixed":          record("", artifact.HTTPHeadersFormat, "extract", "packetCapture", artifact.RecordingNativeLimit, artifact.Digest{}),
		"raw":            record(artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, "raw", "packetCapture", artifact.RecordingNativeLimit, artifact.Digest{}),
		"extract-digest": record(artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, "extract", "packetCapture", artifact.RecordingNativeLimit, analysis.ContextSourceProjectionDigest()),
		"pod-evidence":   record("", artifact.ContextFormat, "metadata", "packetCapture", artifact.MaxContextBytes, analysis.ContextSourceProjectionDigest()),
	} {
		if projectionSource(r) {
			t.Fatalf("%s accepted", name)
		}
	}
}
