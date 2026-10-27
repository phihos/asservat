//go:build cgo && libpcap

package pcap

/*
#cgo LDFLAGS: -l:libpcap.a
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

// asv_compile compiles on a dead Ethernet handle: no device, socket or
// capture is opened. The caller has screened the expression so that no
// host, network, ether or service name can reach libpcap's resolvers.
static int asv_compile(const char *expr, int snaplen, struct bpf_program *prog, char *err, size_t errlen) {
	pcap_t *p = pcap_open_dead(DLT_EN10MB, snaplen);
	if (p == NULL) {
		snprintf(err, errlen, "pcap_open_dead failed");
		return -1;
	}
	int rc = pcap_compile(p, prog, expr, 1, PCAP_NETMASK_UNKNOWN);
	if (rc != 0) {
		snprintf(err, errlen, "%s", pcap_geterr(p));
	}
	pcap_close(p);
	return rc;
}
*/
import "C"

import (
	"errors"
	"strings"
	"sync"
	"unsafe"

	"asservat.local/asservat/internal/adapters/packets"
	value "asservat.local/asservat/internal/domain/planning"
)

// Compiler is the hub's statically linked libpcap filter compiler (S2,
// ADR-243). One compilation per preview; libpcap's compiler state is not
// shared across calls, and the mutex keeps older libpcap builds safe.
type Compiler struct{ mu sync.Mutex }

func NewCompiler() *Compiler { return &Compiler{} }

// Version names the linked libpcap for provenance and diagnostics.
func (c *Compiler) Version() string { return C.GoString(C.pcap_lib_version()) }

func (c *Compiler) CompileFilter(expression string) (value.CompiledFilter, error) {
	if c == nil || expression == "" || len(expression) > value.MaxFilterBytes || strings.IndexByte(expression, 0) >= 0 {
		return value.CompiledFilter{}, errors.New("invalid filter expression")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expr := C.CString(expression)
	defer C.free(unsafe.Pointer(expr))
	var prog C.struct_bpf_program
	var msg [C.PCAP_ERRBUF_SIZE]C.char
	if C.asv_compile(expr, C.int(value.FilterSnaplen), &prog, &msg[0], C.size_t(len(msg))) != 0 {
		return value.CompiledFilter{}, errors.New(C.GoString(&msg[0]))
	}
	defer C.pcap_freecode(&prog)
	n := int(prog.bf_len)
	if n < 1 || n > value.MaxFilterInstructions*16 {
		return value.CompiledFilter{}, errors.New("compiled filter has an unsupported length")
	}
	insns := unsafe.Slice(prog.bf_insns, n)
	out := value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: make([]value.BPFInstruction, n)}
	for i, ins := range insns {
		out.Program[i] = value.BPFInstruction{Code: uint16(ins.code), Jt: uint8(ins.jt), Jf: uint8(ins.jf), K: uint32(ins.k)}
	}
	// ADR-248: the node runs the program in the user-space evaluator, so a
	// program it cannot run exactly is refused here, at preview.
	if len(out.Program) <= value.MaxFilterInstructions && packets.CheckProgram(out.Program) != nil {
		return value.CompiledFilter{}, errors.New("the compiled program uses an instruction the node's packet evaluator does not run (ldx len, neg or an ancillary load); simplify the filter")
	}
	return out, nil
}
