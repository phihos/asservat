package postgres

import (
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
)

func TestPacketProjectionPublishedSourcePinsMetadataAndBound(t *testing.T) {
	s := analysis.ContextProjectionScope{NativeType: artifact.PCAPNGArtifact, SourceFormat: artifact.PCAPNGFormat, DisplayVersion: analysis.PacketSummaryDisplayVersion}
	for _, limit := range []int64{1, 1 << 20, artifact.RecordingNativeLimit} {
		e := artifact.ContextExpectation{NativeType: artifact.PCAPNGArtifact, DataClass: "metadata", Registration: artifact.Registration{NativeLimit: limit}}
		r := app.ContextProjectionEvidence{NativeType: e.NativeType, SourceFormat: artifact.PCAPNGFormat, DataClass: e.DataClass, Retained: privacy.RetainedArtifact{Registration: e.Registration, Input: privacy.Input{EvidenceType: "packetCapture"}}}
		if !scopeSource(s, e) || !projectionSource(r) {
			t.Fatal("published metadata source refused", limit)
		}
		for _, badLimit := range []int64{0, artifact.RecordingNativeLimit + 1} {
			badE, badR := e, r
			badE.Registration.NativeLimit = badLimit
			badR.Retained.Registration.NativeLimit = badLimit
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("unbounded source accepted", badLimit)
			}
		}
		for _, class := range []string{"raw", "extract", ""} {
			badE, badR := e, r
			badE.DataClass = class
			badR.DataClass = class
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("source reclassified", class)
			}
		}
		badR := r
		badR.Retained.Input.EvidenceType = "profile"
		if projectionSource(badR) {
			t.Fatal("unrelated evidence type accepted")
		}
		badR = r
		badR.SourceProjectionDigest = artifact.Digest{1}
		if projectionSource(badR) {
			t.Fatal("projection digest accepted")
		}
		badE, badR := e, r
		badE.NativeType = artifact.RawPCAPNGArtifact
		badR.NativeType = artifact.RawPCAPNGArtifact
		badR.SourceFormat = artifact.RawPCAPNGFormat
		if scopeSource(s, badE) || projectionSource(badR) {
			t.Fatal("raw packets reclassified metadata")
		}
	}
}
