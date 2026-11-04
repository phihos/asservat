package evidence

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestPacketSummaryExpectationRefusesRawOrUnboundedNative(t *testing.T) {
	source, scope, _, _ := httpHeaderPageFixture(t)
	e := &source.Expectation
	e.NativeType = artifact.PCAPNGArtifact
	e.DataClass = "metadata"
	e.Recording.Profile = "networkHeaders"
	e.Recording.Snaplen = artifact.RecordingSnaplen
	e.Recording.HTTP = nil
	scope.NativeType = artifact.PCAPNGArtifact
	scope.SourceFormat = artifact.PCAPNGFormat
	scope.DisplayVersion = query.PacketSummaryDisplayVersion
	scope.Headers = query.HTTPHeaderWindow{}
	if !source.Valid(scope.Version) || !projectionExpectation(*e, scope) {
		t.Fatal("saved networkHeaders source refused", e.Validate())
	}
	bad := *e
	bad.NativeType = artifact.RawPCAPNGArtifact
	bad.DataClass = "raw"
	if projectionExpectation(bad, scope) {
		t.Fatal("raw input passed metadata summary source")
	}
	bad = *e
	bad.Registration.NativeLimit = artifact.RecordingNativeLimit + 1
	if projectionExpectation(bad, scope) {
		t.Fatal("unbounded native input passed summary source")
	}
	wrong := scope
	wrong.Version[0]++
	if source.Valid(wrong.Version) {
		t.Fatal("source copy version changed")
	}
}
