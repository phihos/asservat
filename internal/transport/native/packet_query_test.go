package native

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"reflect"
	"testing"
)

func TestPacketQueryNativeCodecPreservesPrimitiveZeroNullAndScope(t *testing.T) {
	s := resultScope()
	s.NativeType = artifact.PCAPNGArtifact
	s.SourceFormat = artifact.PCAPNGFormat
	s.SourceProjectionDigest = artifact.Digest{}
	s.DisplayVersion = query.PacketQueryDisplayVersion
	s.Selection = query.LineSelection{}
	selection := query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketTCPAck, query.PacketSourcePort}, MaxPackets: 2, MaxScanBytes: 1000}
	s.PacketQuery, _ = selection.Window()
	index, zero := uint32(1), uint32(0)
	page := query.PacketQueryResult{CaptureMode: "networkHeaders", Fields: selection.Fields, Rows: [][]query.PacketQueryCell{{{Number: &index}, {Number: &zero}, {}}}, ScannedBytes: 80, ScannedPackets: 1}
	b, e := encodeProjectionResult(query.ProjectionResult{PacketQuery: &page}, s)
	if e != nil || !bytes.Contains(b, []byte(`[[1,0,null]]`)) {
		t.Fatal("primitivewire", e, string(b))
	}
	back, e := decodeProjectionResult(b, s)
	if e != nil || back.PacketQuery == nil || !reflect.DeepEqual(*back.PacketQuery, page) {
		t.Fatal("roundtrip", e)
	}
	for _, bad := range [][]byte{bytes.Replace(b, []byte(`[[1,0,null]]`), []byte(`[[1,true,null]]`), 1), bytes.Replace(b, []byte(`[[1,0,null]]`), []byte(`[[1,{"number":0},null]]`), 1)} {
		if _, e = decodeProjectionResult(bad, s); e == nil {
			t.Fatal("nonprimitiveaccepted")
		}
	}
	wrong := s
	wrong.NativeType = artifact.RawPCAPNGArtifact
	wrong.SourceFormat = artifact.RawPCAPNGFormat
	wrong.RawGrantID = "00000000-0000-4000-8000-000000000099"
	if _, e = decodeProjectionResult(b, wrong); e == nil {
		t.Fatal("metadataasraw")
	}
}
