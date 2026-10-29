package packets

import (
	"encoding/binary"
	"math"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
	"golang.org/x/net/bpf"
)

func prefixProgram(t testing.TB, instructions ...bpf.Instruction) []value.BPFInstruction {
	t.Helper()
	raw, err := bpf.Assemble(instructions)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]value.BPFInstruction, len(raw))
	for i, r := range raw {
		out[i] = value.BPFInstruction{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return out
}

func TestPrefixProgramReadBoundsAndXWrites(t *testing.T) {
	for _, tc := range []struct {
		name         string
		instructions []bpf.Instruction
		safe         bool
	}{
		{"absolute-end134", []bpf.Instruction{bpf.LoadAbsolute{Off: 130, Size: 4}}, true},
		{"absolute-end135", []bpf.Instruction{bpf.LoadAbsolute{Off: 131, Size: 4}}, false},
		{"indirect-end134", []bpf.Instruction{bpf.LoadConstant{Dst: bpf.RegX, Val: 60}, bpf.LoadIndirect{Off: 70, Size: 4}}, true},
		{"indirect-end135", []bpf.Instruction{bpf.LoadIndirect{Off: 71, Size: 4}}, false},
		{"indirect-overflow32", []bpf.Instruction{bpf.LoadIndirect{Off: math.MaxUint32 - 59, Size: 4}}, false},
		{"msh-end134", []bpf.Instruction{bpf.LoadMemShift{Off: 133}}, true},
		{"msh-end135", []bpf.Instruction{bpf.LoadMemShift{Off: 134}}, false},
		{"constant-X61", []bpf.Instruction{bpf.LoadConstant{Dst: bpf.RegX, Val: 61}}, false},
		{"constant-A-unbounded", []bpf.Instruction{bpf.LoadConstant{Dst: bpf.RegA, Val: math.MaxUint32}}, true},
		{"TAX", []bpf.Instruction{bpf.TAX{}}, false},
		{"scratch-X", []bpf.Instruction{bpf.LoadScratch{Dst: bpf.RegX, N: 0}}, false},
		{"scratch-A-store-X-TXA", []bpf.Instruction{bpf.StoreScratch{Src: bpf.RegX, N: 0}, bpf.LoadScratch{Dst: bpf.RegA, N: 0}, bpf.TXA{}}, true},
		{"unreachable-outside-prefix", []bpf.Instruction{bpf.Jump{Skip: 1}, bpf.LoadAbsolute{Off: 134, Size: 1}}, false},
		{"unreachable-TAX", []bpf.Instruction{bpf.Jump{Skip: 1}, bpf.TAX{}}, false},
		{"malformed-jump", []bpf.Instruction{bpf.Jump{Skip: 100}}, false},
		{"negation", []bpf.Instruction{bpf.NegateA{}}, false},
		{"unsupported-extension", []bpf.Instruction{bpf.LoadExtension{Num: bpf.ExtRand}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instructions := append(tc.instructions, bpf.RetConstant{Val: 65535})
			program := prefixProgram(t, instructions...)
			if got := CheckPrefixProgram(program); (got == nil) != tc.safe {
				t.Fatal("prefix eligibility", tc.name, got, tc.safe)
			}
		})
	}
	for _, program := range [][]value.BPFInstruction{{{Code: 0xffff}}, {{Code: 0x81}, {Code: 6, K: 65535}}} {
		if CheckPrefixProgram(program) == nil {
			t.Fatal("unknown/unsupported instruction accepted")
		}
	}
	if err := CheckPrefixProgram(nil); err != nil {
		t.Fatal("empty accept-all program changed", err)
	}
}

func TestPrefixProofRejectsExistingVMSilentNonmatch(t *testing.T) {
	program := prefixProgram(t, bpf.LoadAbsolute{Off: 134, Size: 1}, bpf.RetA{})
	if err := CheckProgram(program); err != nil {
		t.Fatal("existing opcode checker cannot witness missing prefix proof", err)
	}
	filter, err := NewFilter(program)
	if err != nil {
		t.Fatal(err)
	}
	full := make([]byte, 1514)
	full[134] = 1
	if !filter.Match(full, len(full)) || filter.Match(full[:Snaplen], len(full)) {
		t.Fatal("out-of-prefix read did not demonstrate changed match")
	}
	if CheckPrefixProgram(program) == nil {
		t.Fatal("silent false predicate was accepted")
	}
}

// Numeric program independently pinned against libpcap in the policy fixture:
// tcp[13] & 2 != 0. It selects IPv4 TCP; this is no IPv6/VLAN capability claim.
var prefixTCPFlagsProgram = []value.BPFInstruction{
	{Code: 0x28, K: 12}, {Code: 0x15, Jf: 8, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 6, K: 6},
	{Code: 0x28, K: 20}, {Code: 0x45, Jt: 4, K: 0x1fff}, {Code: 0xb1, K: 14}, {Code: 0x50, K: 27},
	{Code: 0x45, Jf: 1, K: 2}, {Code: 6, K: 65535}, {Code: 6},
}

func TestPrefixProofMaintainedVMMatchesFullPacket(t *testing.T) {
	if err := CheckPrefixProgram(prefixTCPFlagsProgram); err != nil {
		t.Fatal(err)
	}
	filter, err := NewFilter(prefixTCPFlagsProgram)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		ihl      int
		ether    uint16
		fragment uint16
		flag     byte
		want     bool
	}{
		{"IPv4-IHL20-match", 20, 0x800, 0, 2, true}, {"IPv4-IHL60-match", 60, 0x800, 0, 2, true},
		{"IPv4-IHL60-no-match", 60, 0x800, 0, 0, false}, {"IPv4-fragment-offset", 20, 0x800, 1, 2, false},
		{"IPv6-not-selected", 20, 0x86dd, 0, 2, false}, {"VLAN-not-selected", 20, 0x8100, 0, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := make([]byte, 1514)
			binary.BigEndian.PutUint16(full[12:14], tc.ether)
			full[14] = 0x40 | byte(tc.ihl/4)
			full[23] = 6
			binary.BigEndian.PutUint16(full[20:22], tc.fragment)
			full[14+tc.ihl+13] = tc.flag
			a, b := filter.Match(full, len(full)), filter.Match(full[:Snaplen], len(full))
			if a != tc.want || b != a {
				t.Fatal("full/prefix match", a, b, tc.want)
			}
		})
	}
	// Keep the IPv4/TCP selector fields valid so short inputs reach the
	// actual MSH/indirect load rather than failing only the Ethernet test.
	short := make([]byte, Snaplen)
	binary.BigEndian.PutUint16(short[12:14], 0x800)
	short[14], short[23], short[87] = 0x4f, 6, 2
	for _, size := range []int{0, 12, 14, 24, 40, 87} {
		if filter.Match(short[:size], size) {
			t.Fatal("out-of-bounds short input matched", size)
		}
	}
	// Byte 87 is sufficient for this predicate, independently of the later
	// sanitizer's requirement for complete supported transport headers.
	if !filter.Match(short[:88], 88) {
		t.Fatal("actual maximum predicate read changed")
	}
}

func TestPrefixProofPreservesOriginalWireLengthExtension(t *testing.T) {
	program := prefixProgram(t, bpf.LoadExtension{Num: bpf.ExtLen}, bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: Snaplen, SkipFalse: 1}, bpf.RetConstant{Val: 65535}, bpf.RetConstant{Val: 0})
	if err := CheckPrefixProgram(program); err != nil {
		t.Fatal(err)
	}
	filter, err := NewFilter(program)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []int{60, Snaplen, Snaplen + 1, 1514, 65535} {
		full := make([]byte, wire)
		prefix := full[:min(wire, Snaplen)]
		a, b := filter.Match(full, wire), filter.Match(prefix, wire)
		if a != (wire > Snaplen) || b != a {
			t.Fatal("len used captured prefix instead of original wire", wire, a, b)
		}
	}
	rawVM, err := bpf.NewVM([]bpf.Instruction{bpf.LoadExtension{Num: bpf.ExtLen}, bpf.RetA{}})
	if err != nil {
		t.Fatal(err)
	}
	n, err := rawVM.Run(make([]byte, Snaplen))
	if err != nil || n != Snaplen {
		t.Fatal("maintained VM raw ExtLen semantics changed", n, err)
	}
}

func BenchmarkCheckPrefixProgram(b *testing.B) {
	maximum := make([]value.BPFInstruction, value.MaxFilterInstructions)
	for i := range maximum {
		maximum[i] = value.BPFInstruction{Code: 0, K: 1}
	}
	maximum[len(maximum)-1] = value.BPFInstruction{Code: 6, K: 65535}
	for _, tc := range []struct {
		name    string
		program []value.BPFInstruction
	}{{"reviewed-11", prefixTCPFlagsProgram}, {"maximum-256", maximum}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := CheckPrefixProgram(tc.program); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
