package postgres

import (
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
)

func TestRawPacketProjectionPublishedSourcePinsRawAndBound(t *testing.T) {
	s := analysis.ContextProjectionScope{NativeType: artifact.RawPCAPNGArtifact, SourceFormat: artifact.RawPCAPNGFormat, DisplayVersion: "approved-raw-pcap-summary/v1"}
	for _, limit := range []int64{1, 1 << 20, artifact.RecordingNativeLimit} {
		e := artifact.ContextExpectation{NativeType: artifact.RawPCAPNGArtifact, DataClass: "raw", Registration: artifact.Registration{NativeLimit: limit}}
		r := app.ContextProjectionEvidence{NativeType: e.NativeType, SourceFormat: artifact.RawPCAPNGFormat, DataClass: e.DataClass, Retained: privacy.RetainedArtifact{Registration: e.Registration, Input: privacy.Input{EvidenceType: "packetCapture"}}}
		if !scopeSource(s, e) || !projectionSource(r) {
			t.Fatal("published raw source refused", limit)
		}
		for _, class := range []string{"metadata", "extract", ""} {
			badE, badR := e, r
			badE.DataClass, badR.DataClass = class, class
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("raw source reclassified", class)
			}
		}
		for _, n := range []int64{0, artifact.RecordingNativeLimit + 1} {
			badE, badR := e, r
			badE.Registration.NativeLimit, badR.Retained.Registration.NativeLimit = n, n
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("unbounded raw source accepted", n)
			}
		}
		badScope := s
		badScope.DisplayVersion = analysis.PacketSummaryDisplayVersion
		if scopeSource(badScope, e) {
			t.Fatal("raw source accepted metadata display")
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
	}
}
