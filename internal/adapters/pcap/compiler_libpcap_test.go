//go:build cgo && libpcap

package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	planning "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/planning"
	"golang.org/x/net/bpf"
)

// The feasibility corpus (experiments/feasibility/results/filter-programs.json,
// 2026-10-09): libpcap 1.10.4 programs for 11 expressions with one synthetic
// Ethernet frame each and the expected verdict. The same programs passed the
// VM kernel verifier and BPF_PROG_TEST_RUN there; this test needs no kernel.
type corpusCase struct {
	Filter       string
	Packet       []byte
	Instructions []bpf.RawInstruction
	Want         bool
}

func corpus(t *testing.T) []corpusCase {
	t.Helper()
	b, err := os.ReadFile("testdata/feasibility-filter-programs.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(b, &cases); err != nil || len(cases) != 11 {
		t.Fatalf("corpus: %v (%d cases)", err, len(cases))
	}
	return cases
}

func run(t *testing.T, program []value.BPFInstruction, packet []byte) bool {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(program))
	for i, ins := range program {
		raw[i] = bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	instructions, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatalf("libpcap emitted an instruction x/net/bpf cannot decode: %v", raw)
	}
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}
	n, err := vm.Run(packet)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestFeasibilityCorpusVerdicts(t *testing.T) {
	c := NewCompiler()
	if !strings.Contains(c.Version(), "1.11.0") {
		t.Fatalf("linked %q, want the pinned libpcap 1.11.0", c.Version())
	}
	for _, tc := range corpus(t) {
		f, err := c.CompileFilter(tc.Filter)
		if err != nil {
			t.Fatalf("%s: %v", tc.Filter, err)
		}
		if f.LinkType != value.FilterLinkType || f.Snaplen != value.FilterSnaplen || len(f.Program) < 1 || len(f.Program) > value.MaxFilterInstructions {
			t.Fatalf("%s: unexpected program shape %+v", tc.Filter, f)
		}
		if got := run(t, f.Program, tc.Packet); got != tc.Want {
			t.Fatalf("%s: verdict %v, want %v", tc.Filter, got, tc.Want)
		}
		// The recorded 1.10.4 program and the pinned 1.11.0 program agree on
		// the recorded frame; exact bytecode may differ between versions.
		recorded := make([]value.BPFInstruction, len(tc.Instructions))
		for i, ins := range tc.Instructions {
			recorded[i] = value.BPFInstruction{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		if run(t, recorded, tc.Packet) != tc.Want {
			t.Fatalf("%s: corpus program does not match its own verdict", tc.Filter)
		}
	}
}

// The recorded IPv6 case that Gadget's bundled compiler rejected compiles with
// libpcap and survives the planner's screening and bounds.
func TestRecordedIPv6CaseThroughPlanner(t *testing.T) {
	c := NewCompiler()
	expression := "ip6 and dst host 2001:db8::2"
	if err := planning.ScreenFilter("filter", expression); err != nil {
		t.Fatal(err)
	}
	f, err := c.CompileFilter(expression)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus(t) {
		if tc.Filter == expression && !run(t, f.Program, tc.Packet) {
			t.Fatal("IPv6 destination frame not matched")
		}
	}
	if planning.FilterProgramDigest(f.Program) == planning.FilterProgramDigest(f.Program[:len(f.Program)-1]) {
		t.Fatal("program digest ignores instructions")
	}
}

func TestCompilerRejectsInvalidSyntax(t *testing.T) {
	c := NewCompiler()
	for _, expression := range []string{"tcp port", "host 999.1.1.1", "port 70000", "ip and and tcp"} {
		if _, err := c.CompileFilter(expression); err == nil {
			t.Fatalf("%q compiled", expression)
		}
	}
	if _, err := c.CompileFilter(strings.Repeat("x", value.MaxFilterBytes+1)); err == nil {
		t.Fatal("oversized expression reached libpcap")
	}
}

// A filter that screens within 256 tokens can still compile to more than 256
// instructions; the planner refuses it with a remedy instead of truncating.
func TestInstructionBoundThroughPlanner(t *testing.T) {
	var parts []string
	for i := 1; i <= 60; i++ {
		parts = append(parts, fmt.Sprintf("port %d", 1000+i))
	}
	expression := strings.Join(parts, " or ")
	if err := planning.ScreenFilter("filter", expression); err != nil {
		t.Fatal(err)
	}
	f, err := NewCompiler().CompileFilter(expression)
	if err != nil || len(f.Program) <= value.MaxFilterInstructions {
		t.Fatalf("expected more than %d instructions: %d, %v", value.MaxFilterInstructions, len(f.Program), err)
	}
	c := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []value.ProfileEdit{{ActionID: "sample", Field: "packetFilter", Text: expression}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	var refusal value.CompositionError
	if err := planning.ValidateComposition(c, NewCompiler()); !errors.As(err, &refusal) || refusal.Code != value.CompositionFilterRejected || !strings.Contains(refusal.Reason, "instructions") {
		t.Fatalf("got %v", err)
	}
	c.Components[0].Edits[0].Text = "tcp port 8080"
	if err := planning.ValidateComposition(c, NewCompiler()); err != nil {
		t.Fatal(err)
	}
}

// The pinned libpcap compiles the recorder fixture expression to exactly the
// program in examples/resolved-recorder-preview.json, so that fixture's
// execution digest is the one a real hub computes.
func TestRecorderFixtureProgramPinned(t *testing.T) {
	b, err := readImplementedExample("../../../examples/", "resolved-recorder-preview.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Filters []struct {
			Expression    string      `json:"expression"`
			Program       [][4]uint32 `json:"program"`
			ProgramDigest string      `json:"programDigest"`
		} `json:"filters"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil || len(fixture.Filters) != 1 {
		t.Fatal(err)
	}
	f, err := NewCompiler().CompileFilter(fixture.Filters[0].Expression)
	if err != nil {
		t.Fatal(err)
	}
	got := make([][4]uint32, len(f.Program))
	for i, ins := range f.Program {
		got[i] = [4]uint32{uint32(ins.Code), uint32(ins.Jt), uint32(ins.Jf), ins.K}
	}
	d := planning.FilterProgramDigest(f.Program)
	if fmt.Sprint(got) != fmt.Sprint(fixture.Filters[0].Program) || hex.EncodeToString(d[:]) != fixture.Filters[0].ProgramDigest {
		t.Fatalf("libpcap program %v differs from the fixture", got)
	}
}

// frame builds a synthetic Ethernet frame carrying an IPv4 or IPv6 TCP
// segment between src and dst on the given ports.
func frame(src, dst netip.Addr, sport, dport uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4
	eth := make([]byte, 14)
	if src.Is4() {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:], 40)
		s, d := src.As4(), dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		return append(append(eth, ip...), tcp...)
	}
	binary.BigEndian.PutUint16(eth[12:], 0x86dd)
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(ip[4:], 20)
	s, d := src.As16(), dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(append(eth, ip...), tcp...)
}

// capturing keeps the programs the planner compiled with the real libpcap.
type capturing struct{ programs []value.CompiledFilter }

func (c *capturing) CompileFilter(expression string) (value.CompiledFilter, error) {
	f, err := NewCompiler().CompileFilter(expression)
	if err == nil {
		c.programs = append(c.programs, f)
	}
	return f, err
}

// ADR-283: the planner's generated CIDR peer expression compiles with the
// pinned libpcap, and the program matches only peer traffic: a user
// `or host` term cannot admit a non-peer (SC-NET-001).
func TestCIDRPeersThroughPlanner(t *testing.T) {
	edits := []value.ProfileEdit{
		{ActionID: "sample", Field: "packetPeers", Peers: &value.PeerSelection{CIDRs: [][]string{{"10.0.0.0/24", "2001:db8::/64"}}, Protocol: "tcp", Ports: []int{5432}, Resolution: "frozen", MaxEndpoints: 1, MaxStaleness: "5s"}},
		{ActionID: "sample", Field: "packetFilter", Text: "tcp or host 203.0.113.9"},
	}
	c := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: edits}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
	// Every rendered form compiles: host prefixes, default routes, ICMP of
	// both families and ports without a transport.
	for _, peers := range []*value.PeerSelection{
		{CIDRs: [][]string{{"10.1.2.3", "2001:db8::1", "0.0.0.0/0"}}, Protocol: "icmp", Resolution: "follow", MaxEndpoints: 1, MaxStaleness: "5s"},
		{CIDRs: [][]string{{"::/0"}, {"192.168.0.0/16"}}, Protocol: "any", Ports: []int{53, 443}, Resolution: "frozen", MaxEndpoints: 1, MaxStaleness: "5s"},
		{CIDRs: [][]string{{"fd00::/8"}}, Protocol: "udp", Resolution: "frozen", MaxEndpoints: 1, MaxStaleness: "5s"},
	} {
		one := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: c.Components[0].Profile, Edits: []value.ProfileEdit{{ActionID: "sample", Field: "packetPeers", Peers: peers}}}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
		if err := planning.ValidateComposition(one, NewCompiler()); err != nil {
			t.Fatalf("%+v: %v", peers, err)
		}
	}
	compiler := &capturing{}
	if err := planning.ValidateComposition(c, compiler); err != nil || len(compiler.programs) != 1 {
		t.Fatal(err)
	}
	f := compiler.programs[0]
	pod4, pod6 := netip.MustParseAddr("10.244.0.5"), netip.MustParseAddr("fd00::5")
	for name, tc := range map[string]struct {
		packet []byte
		want   bool
	}{
		"ipv4 peer":        {frame(pod4, netip.MustParseAddr("10.0.0.7"), 40000, 5432), true},
		"ipv4 peer reply":  {frame(netip.MustParseAddr("10.0.0.7"), pod4, 5432, 40000), true},
		"ipv6 peer":        {frame(pod6, netip.MustParseAddr("2001:db8::7"), 40000, 5432), true},
		"other port":       {frame(pod4, netip.MustParseAddr("10.0.0.7"), 40000, 443), false},
		"user or host":     {frame(pod4, netip.MustParseAddr("203.0.113.9"), 40000, 5432), false},
		"outside prefix":   {frame(pod4, netip.MustParseAddr("10.0.1.7"), 40000, 5432), false},
		"outside prefix 6": {frame(pod6, netip.MustParseAddr("2001:db8:0:1::7"), 40000, 5432), false},
	} {
		if got := run(t, f.Program, tc.packet); got != tc.want {
			t.Errorf("%s: matched %v", name, got)
		}
	}
}

// readImplementedExample reads the example this runtime implements:
// examples/implemented/ (pre-ADR-330 contracts) when present, otherwise the
// canonical example.
func readImplementedExample(dir, name string) ([]byte, error) {
	if b, err := os.ReadFile(dir + "implemented/" + name); err == nil {
		return b, nil
	}
	return os.ReadFile(dir + name)
}
