package contracts

import (
	"encoding/json"
	"testing"
)

func TestPacketQueryCellPrimitiveWire(t *testing.T) {
	zero, maximum := uint32(0), ^uint32(0)
	text := "0102"
	for _, tc := range []struct {
		name string
		cell PacketQueryCell
		wire string
	}{{"null", PacketQueryCell{}, "null"}, {"zero", PacketQueryCell{Number: &zero}, "0"}, {"uint32", PacketQueryCell{Number: &maximum}, "4294967295"}, {"text", PacketQueryCell{Text: &text}, `"0102"`}} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := json.Marshal(tc.cell)
			if err != nil || string(wire) != tc.wire {
				t.Fatalf("primitive cell = %s, %v; want %s", wire, err, tc.wire)
			}
			var decoded PacketQueryCell
			if err = json.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			again, err := json.Marshal(decoded)
			if err != nil || string(again) != tc.wire {
				t.Fatalf("round trip = %s, %v", again, err)
			}
		})
	}
	if _, err := json.Marshal(PacketQueryCell{Text: &text, Number: &zero}); err == nil {
		t.Fatal("ambiguous cell was serialized")
	}
}

func TestPacketQueryCellRejectsOtherWireTypes(t *testing.T) {
	for _, wire := range []string{`true`, `false`, `{}`, `[]`, `{"number":1}`, `-1`, `-0`, `0.0`, `1e2`, `4294967296`, `"\ud800"`, "\"\xff\""} {
		t.Run(wire, func(t *testing.T) {
			var cell PacketQueryCell
			if err := json.Unmarshal([]byte(wire), &cell); err == nil {
				t.Fatal("nonprimitive/invalid cell accepted")
			}
		})
	}
}
