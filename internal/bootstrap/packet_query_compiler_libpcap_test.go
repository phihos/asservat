//go:build cgo && libpcap

package bootstrap

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/pcap"
	query "asservat.local/asservat/internal/domain/analysis"
	planning "asservat.local/asservat/internal/domain/planning"
)

// Exercise the production query compiler with the pinned user-space library,
// then evaluate only the retained prefix. No device or kernel hook is opened.
func TestPacketQueryPinnedLibpcapWireLengthAndTruncation(t *testing.T) {
	compiler := publicPacketQueryCompiler{inner: pcap.NewCompiler()}
	frame := make([]byte, 54)
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	frame[14], frame[23] = 0x45, 6
	binary.BigEndian.PutUint16(frame[16:], 40)
	copy(frame[26:], []byte{127, 0, 0, 1, 127, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[34:], 12345)
	binary.BigEndian.PutUint16(frame[36:], 8080)
	frame[46], frame[47] = 0x50, 0x12
	for _, tc := range []struct {
		filter string
		prefix []byte
		wire   int
		want   bool
	}{
		{"tcp port 8080 and len > 100", frame, 200, true},
		{"tcp port 8080 and len > 100", frame, 54, false},
		{"ip and src host 127.0.0.1 and dst port 8080", frame, 200, true},
		{"ip and src host 127.0.0.1 and dst port 8080", frame[:14], 200, false},
		{"udp port 8080", frame, 200, false},
	} {
		program, err := compiler.CompilePacketQueryFilter(t.Context(), tc.filter)
		if err != nil || !program.Valid() {
			t.Fatal("compile", tc.filter, err)
		}
		instructions := make([]planning.BPFInstruction, len(program.Instructions))
		for i, instruction := range program.Instructions {
			instructions[i] = planning.BPFInstruction{Code: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
		}
		filter, err := packets.NewFilter(instructions)
		if err != nil || filter.Match(tc.prefix, tc.wire) != tc.want {
			t.Fatal("retained prefix/original wire verdict", tc.filter, tc.wire, err)
		}
	}
	for _, expression := range []string{"tcp[13] & 2 != 0", "host example.invalid", strings.Repeat(" ", 513)} {
		if _, err := compiler.CompilePacketQueryFilter(t.Context(), expression); !errors.Is(err, query.ErrInvalid) {
			t.Fatal("unsupported query accepted", expression, err)
		}
	}
}
