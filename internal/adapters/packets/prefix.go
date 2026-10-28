package packets

import (
	value "asservat.local/asservat/internal/domain/planning"
	"golang.org/x/net/bpf"
)

// CheckPrefixProgram conservatively proves that a supported program needs no
// packet bytes beyond the existing Snaplen. It is an unwired prerequisite for
// sensitive predicates, not collection authority. Runtime still must supply the
// entire min(original wire length, Snaplen) prefix and independently meter input.
//
// X starts at zero; the only allowed writes keep it <=60. All instructions,
// including unreachable ones, must fit that global bound. There is no branch
// interpreter, packet parser, instruction rewriting or per-frame work here.
func CheckPrefixProgram(program []value.BPFInstruction) error {
	if err := CheckProgram(program); err != nil {
		return err
	}
	const maxX = uint64(60) // LoadMemShift computes 4*(packet byte & 15).
	for _, ins := range program {
		decoded := (bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}).Disassemble()
		switch d := decoded.(type) {
		case bpf.LoadAbsolute:
			if uint64(d.Off)+uint64(d.Size) > Snaplen {
				return ErrFilterUnsupported
			}
		case bpf.LoadIndirect:
			if uint64(d.Off)+maxX+uint64(d.Size) > Snaplen {
				return ErrFilterUnsupported
			}
		case bpf.LoadMemShift:
			if uint64(d.Off)+1 > Snaplen {
				return ErrFilterUnsupported
			}
		case bpf.LoadConstant:
			if d.Dst == bpf.RegX && uint64(d.Val) > maxX {
				return ErrFilterUnsupported
			}
		case bpf.LoadScratch:
			if d.Dst == bpf.RegX {
				return ErrFilterUnsupported
			}
		case bpf.LoadExtension:
			// CheckProgram permits only LDlenA; Filter.vmFor specializes it from
			// original Wire, not the captured slice length used by the raw VM.
			if d.Num != bpf.ExtLen {
				return ErrFilterUnsupported
			}
		case bpf.StoreScratch, bpf.ALUOpConstant, bpf.ALUOpX, bpf.Jump, bpf.JumpIf, bpf.JumpIfX, bpf.RetA, bpf.RetConstant, bpf.TXA:
			// These may change A/scratch/control flow, never X or packet memory.
		default:
			// TAX, unknown instructions or future writes cannot establish X<=60.
			return ErrFilterUnsupported
		}
	}
	return nil
}
