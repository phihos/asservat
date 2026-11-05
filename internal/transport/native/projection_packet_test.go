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

func TestRawPacketSummaryNativeCodecBindsModeAndUnclassifiedCount(t *testing.T) {
	s := resultScope()
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, query.RawPacketSummaryDisplayVersion
	s.SourceProjectionDigest, s.Selection = artifact.Digest{}, query.LineSelection{}
	unclassified := int64(1)
	summary := query.PacketSummary{CaptureMode: "rawPackets", Packets: 3, UnclassifiedPackets: &unclassified, DropReporting: "unavailable", Conversations: []query.PacketConversation{{Source: "192.0.2.1:1", Destination: "192.0.2.2:2", Protocol: "TCP", Packets: 2}}, ConversationsTotal: 1}
	encoded, err := encodeProjectionResult(query.ProjectionResult{PacketSummary: &summary}, s)
	if err != nil {
		t.Fatal(err)
	}
	result, err := decodeProjectionResult(encoded, s)
	if err != nil || result.PacketSummary == nil || !reflect.DeepEqual(*result.PacketSummary, summary) {
		t.Fatal("raw fixed aggregate lost its native result", err)
	}
	metadata := s
	metadata.NativeType, metadata.SourceFormat, metadata.DisplayVersion = artifact.PCAPNGArtifact, artifact.PCAPNGFormat, query.PacketSummaryDisplayVersion
	if _, err := decodeProjectionResult(encoded, metadata); err == nil {
		t.Fatal("raw result accepted as metadata")
	}
	for _, bad := range [][]byte{bytes.Replace(encoded, []byte(`"unclassified_packets":1`), []byte(`"unclassified_packets":null`), 1), bytes.Replace(encoded, []byte(`"unclassified_packets":1`), []byte(`"unclassified_packets":4`), 1), append(bytes.Clone(encoded), '}')} {
		if _, err := decodeProjectionResult(bad, s); err == nil {
			t.Fatal("raw result lost required bounded unclassified count")
		}
	}
}
