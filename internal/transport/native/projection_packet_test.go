package native

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestPacketSummaryNativeCodecClosedAndScopeBound(t *testing.T) {
	s := resultScope()
	s.NativeType = artifact.PCAPNGArtifact
	s.SourceFormat = artifact.PCAPNGFormat
	s.SourceProjectionDigest = artifact.Digest{}
	s.DisplayVersion = query.PacketSummaryDisplayVersion
	s.Selection = query.LineSelection{}
	summary := query.PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []query.PacketConversation{}}
	b, err := encodeProjectionResult(query.ProjectionResult{PacketSummary: &summary}, s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeProjectionResult(b, s)
	if err != nil || back.PacketSummary == nil || !reflect.DeepEqual(summary, *back.PacketSummary) {
		t.Fatal("closed packet summary did not roundtrip", err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(b), '}'), bytes.Replace(b, []byte(`"capture_mode":`), []byte(`"extra":true,"capture_mode":`), 1), bytes.Replace(b, []byte(`"packets":0`), []byte(`"packets":-1`), 1), bytes.Replace(b, []byte(`"conversations":[]`), []byte(`"conversations":null`), 1)} {
		if _, err := decodeProjectionResult(bad, s); err == nil {
			t.Fatal("malformed/extra/invalid packet summary accepted")
		}
	}
	wrong := s
	wrong.NativeType = artifact.RawPCAPNGArtifact
	if _, err := decodeProjectionResult(b, wrong); err == nil {
		t.Fatal("metadata result accepted raw scope")
	}
	mixed := query.ProjectionResult{PacketSummary: &summary, Summary: &query.ProfileSummary{}}
	if _, err := encodeProjectionResult(mixed, s); err == nil {
		t.Fatal("mixed result branches serialized")
	}
	var encoded map[string]any
	if json.Unmarshal(b, &encoded) != nil || encoded["drop_reporting"] != "unavailable" {
		t.Fatal("packet native result changed public summary value")
	}
}
