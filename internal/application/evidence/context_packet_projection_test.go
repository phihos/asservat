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

func TestRawPacketSummaryExpectationPinsOriginalRawRecording(t *testing.T) {
	source, scope, _, _ := httpHeaderPageFixture(t)
	e := &source.Expectation
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "raw"
	e.Recording = e.Recording.Clone()
	e.Recording.Profile, e.Recording.Snaplen, e.Recording.HTTP = "rawPackets", 96, nil
	e.Recording.RequireApproval = true
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, query.RawPacketSummaryDisplayVersion
	scope.Headers = query.HTTPHeaderWindow{}
	if !source.Valid(scope.Version) {
		t.Fatal("invalid raw fixture", e.Validate())
	}
	if !projectionExpectation(*e, scope) {
		t.Fatal("exact published raw source denied fixed aggregate")
	}
	wrong := scope
	wrong.NativeType, wrong.SourceFormat, wrong.DisplayVersion = artifact.PCAPNGArtifact, artifact.PCAPNGFormat, query.PacketSummaryDisplayVersion
	if projectionExpectation(*e, wrong) {
		t.Fatal("original raw silently reclassified as metadata")
	}
	changed := *e
	changed.Recording = e.Recording.Clone()
	changed.Recording.Profile = "networkHeaders"
	if projectionExpectation(changed, scope) {
		t.Fatal("raw type accepted metadata recording")
	}
}
