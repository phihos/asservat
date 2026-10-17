package main

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
	"os"
)

type input struct {
	Filter       string
	Packet       []byte
	Instructions []bpf.RawInstruction
	Want         bool
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	if _, e := os.Stat("/root/ASSERVAT_DISPOSABLE_VM"); e != nil {
		panic("VM guard absent")
	}
	raw, e := os.ReadFile("/root/filter-programs.json")
	must(e)
	var cases []input
	must(json.Unmarshal(raw, &cases))
	passed := 0
	for _, c := range cases {
		classic, all := bpf.Disassemble(c.Instructions)
		if !all {
			panic("unsupported cBPF instruction")
		}
		body, e := cbpfc.ToEBPF(classic, cbpfc.EBPFOpts{PacketStart: asm.R2, PacketEnd: asm.R3, Result: asm.R0, ResultLabel: "result", Working: [4]asm.Register{asm.R4, asm.R5, asm.R6, asm.R7}, LabelPrefix: "filter"})
		must(e)
		ins := asm.Instructions{asm.LoadMem(asm.R2, asm.R1, 0, asm.Word), asm.LoadMem(asm.R3, asm.R1, 4, asm.Word)}
		ins = append(ins, body...)
		ins = append(ins, asm.JEq.Imm(asm.R0, 0, "reject").WithSymbol("result"), asm.Mov.Imm(asm.R0, 2), asm.Return(), asm.Mov.Imm(asm.R0, 1).WithSymbol("reject"), asm.Return())
		p, e := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "asservat_filter", Type: ebpf.XDP, Instructions: ins, License: "Dual BSD/GPL"})
		must(e)
		packet := c.Packet
		if len(packet) < 64 {
			packet = append(packet, make([]byte, 64-len(packet))...)
		}
		retval, _, e := p.Test(packet)
		p.Close()
		must(e)
		if (retval == 2) != c.Want {
			panic(fmt.Sprintf("filter mismatch %s result %d", c.Filter, retval))
		}
		passed++
	}
	b, _ := json.Marshal(map[string]any{"cases": passed, "result": "pass", "scope": "real libpcap cBPF -> Gadget's cbpfc dependency -> VM kernel verifier and BPF_PROG_TEST_RUN, Ethernet corpus only; not Gadget operator injection or live kernel attachment"})
	fmt.Println(string(b))
}
