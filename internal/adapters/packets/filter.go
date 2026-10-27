package packets

import (
	"errors"
	"sync"

	value "asservat.local/asservat/internal/domain/planning"
	"golang.org/x/net/bpf"
)

// ErrFilterUnsupported is a hub-compiled program that this evaluator cannot
// run exactly. The hub refuses such a filter at preview (CheckProgram), so a
// node meets it only for a plan from another build.
var ErrFilterUnsupported = errors.New("packet filter program not supported by the node evaluator")

const (
	opLoadLenA = 0x80 // BPF_LD|BPF_W|BPF_LEN
	opLoadLenX = 0x81 // BPF_LDX|BPF_W|BPF_LEN
)

// Filter runs one hub-compiled classic BPF program (S2: the node never
// compiles) on each frame with the maintained golang.org/x/net/bpf
// interpreter. The gadget hands over at most Snaplen bytes per frame, so the
// program's packet-length loads (libpcap's len, less, greater) are replaced by
// the frame's original wire length, as the kernel would see it.
type Filter struct {
	program []bpf.Instruction
	lengths []int // indexes of ld len
	vm      *bpf.VM

	// A program with ld len is specialized once per distinct wire length
	// and reused (bpf.VM.Run keeps no state, so a VM is safe to share).
	mu     sync.Mutex
	byWire map[uint32]*bpf.VM
}

// maxWireVMs bounds the per-wire-length cache. Pod traffic has at most a
// few thousand distinct lengths (≤ MTU); a length beyond the bound is
// specialized for that frame only.
const maxWireVMs = 4096

// CheckProgram reports whether the evaluator runs program exactly: every
// instruction decodes, no ancillary data load other than the packet length,
// no ldx len and no negation (the interpreter implements neither).
func CheckProgram(program []value.BPFInstruction) error {
	_, err := NewFilter(program)
	return err
}

// NewFilter prepares program. An empty program accepts every frame.
func NewFilter(program []value.BPFInstruction) (*Filter, error) {
	if len(program) == 0 {
		return &Filter{}, nil
	}
	if len(program) > value.MaxFilterInstructions {
		return nil, ErrFilterUnsupported
	}
	f := &Filter{program: make([]bpf.Instruction, len(program))}
	for i, ins := range program {
		if ins.Code == opLoadLenX {
			return nil, ErrFilterUnsupported
		}
		d := bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}.Disassemble()
		switch d := d.(type) {
		case bpf.RawInstruction, bpf.NegateA:
			return nil, ErrFilterUnsupported
		case bpf.LoadExtension:
			if d.Num != bpf.ExtLen || ins.Code != opLoadLenA {
				return nil, ErrFilterUnsupported
			}
			f.lengths = append(f.lengths, i)
		}
		f.program[i] = d
	}
	vm, err := bpf.NewVM(f.program)
	if err != nil {
		return nil, ErrFilterUnsupported
	}
	f.vm = vm
	return f, nil
}

// Match reports whether the program accepts frame (the captured prefix)
// whose original length on the wire was wire.
func (f *Filter) Match(frame []byte, wire int) bool {
	if f.vm == nil {
		return true
	}
	vm := f.vm
	if len(f.lengths) > 0 {
		var err error
		if vm, err = f.vmFor(uint32(wire)); err != nil {
			return false
		}
	}
	n, err := vm.Run(frame)
	return err == nil && n > 0
}

// vmFor returns the program specialized for wire, building it at most once
// per distinct length while the cache has room.
func (f *Filter) vmFor(wire uint32) (*bpf.VM, error) {
	f.mu.Lock()
	vm, ok := f.byWire[wire]
	f.mu.Unlock()
	if ok {
		return vm, nil
	}
	program := append([]bpf.Instruction(nil), f.program...)
	for _, i := range f.lengths {
		program[i] = bpf.LoadConstant{Dst: bpf.RegA, Val: wire}
	}
	vm, err := bpf.NewVM(program)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if f.byWire == nil {
		f.byWire = map[uint32]*bpf.VM{}
	}
	if len(f.byWire) < maxWireVMs {
		f.byWire[wire] = vm
	}
	f.mu.Unlock()
	return vm, nil
}
