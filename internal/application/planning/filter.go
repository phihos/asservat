package planning

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// FilterCompiler compiles one screened pcap-filter expression with the pinned
// link type and snapshot length (S2). The hub adapter statically links libpcap;
// a build without it returns value.ErrFilterCompilerUnavailable.
type FilterCompiler interface {
	CompileFilter(expression string) (value.CompiledFilter, error)
}

// filterKeywords are the pcap-filter(7) primitives and qualifiers accepted in
// this release. Anything else that looks like a name is refused before libpcap
// sees it, because libpcap would resolve host, network, ether and service names
// (DNS, /etc/hosts, /etc/ethers, /etc/services) during compilation. gateway is
// excluded for the same reason; inbound/outbound need a capture handle.
var filterKeywords = map[string]bool{
	"and": true, "or": true, "not": true,
	"src": true, "dst": true, "host": true, "net": true, "mask": true, "port": true, "portrange": true,
	"ether": true, "ip": true, "ip6": true, "arp": true, "rarp": true,
	"tcp": true, "udp": true, "icmp": true, "icmp6": true, "sctp": true, "igmp": true, "pim": true, "vrrp": true, "ah": true, "esp": true,
	"proto": true, "protochain": true, "less": true, "greater": true, "len": true,
	"broadcast": true, "multicast": true, "vlan": true, "mpls": true,
}

func filterRefusal(code, path, reason string) error {
	return value.CompositionError{Code: code, Path: path, Reason: reason}
}

// NormalizeFilter trims and collapses whitespace. The normalized text is what
// is compiled, stored in the plan and shown in the preview.
func NormalizeFilter(expression string) string {
	return strings.Join(strings.Fields(expression), " ")
}

// RawBytePredicate reports a raw byte comparison (proto[offset]). It can test
// payload bytes even when only headers are retained, so the plan needs an
// individual sensitive-acquisition approval (ADR-249, REQ-AUT-006).
func RawBytePredicate(expression string) bool {
	return strings.ContainsAny(expression, "[]")
}

// ScreenFilter enforces the REQ-NET-001 bounds before compilation: at most
// 4,096 bytes and 256 syntax tokens of printable ASCII and no name that
// libpcap would resolve. A raw byte comparison passes screening; the
// compiler marks its plan as needing approval (RawBytePredicate).
func ScreenFilter(path, expression string) error {
	if len(expression) > value.MaxFilterBytes {
		return filterRefusal(value.CompositionFilterRejected, path, fmt.Sprintf("the filter has %d bytes; at most %d are allowed", len(expression), value.MaxFilterBytes))
	}
	if strings.TrimSpace(expression) == "" {
		return filterRefusal(value.CompositionFilterRejected, path, "the filter is empty; omit the edit to record all traffic of the selected pod")
	}
	for i := 0; i < len(expression); i++ {
		c := expression[i]
		if c == '\t' || c == '\n' || c == '\r' || c == ' ' {
			continue
		}
		if c < 0x21 || c > 0x7e {
			return filterRefusal(value.CompositionFilterRejected, path, "the filter must be printable ASCII pcap-filter syntax")
		}
	}
	tokens, err := filterTokens(expression)
	if err != nil {
		return filterRefusal(value.CompositionFilterRejected, path, err.Error())
	}
	if len(tokens) > value.MaxFilterTokens {
		return filterRefusal(value.CompositionFilterRejected, path, fmt.Sprintf("the filter has %d syntax tokens; at most %d are allowed", len(tokens), value.MaxFilterTokens))
	}
	for _, t := range tokens {
		if t == "\\" {
			return filterRefusal(value.CompositionFilterRejected, path, "escaped names such as \\tcp are looked up by name; use the protocol number, for example ip proto 6")
		}
	}
	prev, depth := "", 0
	for _, t := range tokens {
		switch t {
		case "[":
			depth++
		case "]":
			depth--
		}
		if !filterWord(t[0]) {
			prev = t
			continue
		}
		// Inside proto[offset:size] the size suffix is 1, 2 or 4 (ADR-249).
		if offset, size, ok := strings.Cut(t, ":"); ok && depth > 0 && (size == "1" || size == "2" || size == "4") {
			if _, err := strconv.ParseUint(offset, 0, 16); err == nil {
				prev = t
				continue
			}
		}
		// libpcap lexes a hyphenated token as a name everywhere except as a
		// portrange operand, so `host 1-2` would reach getaddrinfo.
		if strings.Contains(t, "-") && !strings.Contains(t, ":") {
			if prev != "portrange" || !filterLiteral(t) {
				return filterRefusal(value.CompositionFilterRejected, path, fmt.Sprintf("unsupported filter term %q: a hyphenated range is only valid after portrange; names are never resolved", t))
			}
			prev = t
			continue
		}
		prev = t
		if filterKeywords[t] || filterLiteral(t) {
			continue
		}
		return filterRefusal(value.CompositionFilterRejected, path, fmt.Sprintf("unsupported filter term %q: names are never resolved; use an IP address, CIDR, MAC address, numeric port or a supported primitive (host, net, port, portrange, tcp, udp, icmp, ip, ip6, ...)", t))
	}
	return nil
}

func filterWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// filterTokens splits the expression into words (letters, digits and . : - _)
// and single punctuation characters. It is a bound and screening aid, not a
// parser: libpcap remains the only grammar.
func filterTokens(expression string) ([]string, error) {
	var tokens []string
	for i := 0; i < len(expression); {
		c := expression[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case filterWord(c):
			j := i
			for j < len(expression) && (filterWord(expression[j]) || expression[j] == '.' || expression[j] == ':' || expression[j] == '-') {
				j++
			}
			tokens = append(tokens, expression[i:j])
			i = j
		case strings.IndexByte("()[]!&|=<>+-*/%^:\\", c) >= 0:
			tokens = append(tokens, expression[i:i+1])
			i++
		default:
			return nil, errors.New("unsupported character " + strconv.QuoteRune(rune(c)) + " in the filter")
		}
		if len(tokens) > value.MaxFilterTokens {
			return tokens, nil
		}
	}
	return tokens, nil
}

// filterLiteral accepts numbers, port ranges, IPv4/IPv6 addresses (CIDR
// prefixes are separate tokens) and MAC addresses.
func filterLiteral(t string) bool {
	if _, err := strconv.ParseUint(t, 0, 32); err == nil {
		return true
	}
	if a, b, ok := strings.Cut(t, "-"); ok {
		_, e1 := strconv.ParseUint(a, 10, 16)
		_, e2 := strconv.ParseUint(b, 10, 16)
		return e1 == nil && e2 == nil
	}
	if strings.Contains(t, ":") {
		if _, err := netip.ParseAddr(t); err == nil {
			return true
		}
		parts := strings.Split(t, ":")
		if len(parts) != 6 {
			return false
		}
		for _, p := range parts {
			if _, err := strconv.ParseUint(p, 16, 8); err != nil || len(p) > 2 {
				return false
			}
		}
		return true
	}
	parts := strings.Split(t, ".")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil || n > 255 || p == "" {
			return false
		}
	}
	return true
}

// FilterProgramDigest binds the exact classic BPF program the node will run:
// SHA-256 over each instruction as little-endian struct sock_filter bytes.
func FilterProgramDigest(program []value.BPFInstruction) artifact.Digest {
	h := sha256.New()
	var b [8]byte
	for _, ins := range program {
		binary.LittleEndian.PutUint16(b[0:2], ins.Code)
		b[2], b[3] = ins.Jt, ins.Jf
		binary.LittleEndian.PutUint32(b[4:8], ins.K)
		h.Write(b[:])
	}
	return artifact.Digest(h.Sum(nil))
}

// compileFilter screens, compiles and checks one expression.
func compileFilter(compiler FilterCompiler, path, expression string) (value.CompiledFilter, error) {
	if err := ScreenFilter(path, expression); err != nil {
		return value.CompiledFilter{}, err
	}
	if compiler == nil {
		return value.CompiledFilter{}, filterRefusal(value.CompositionNoCompiler, path, "this hub build has no packet filter compiler; ask an administrator for a hub image built with libpcap, or omit the filter")
	}
	f, err := compiler.CompileFilter(NormalizeFilter(expression))
	switch {
	case errors.Is(err, value.ErrFilterCompilerUnavailable):
		return value.CompiledFilter{}, filterRefusal(value.CompositionNoCompiler, path, "this hub build has no packet filter compiler; ask an administrator for a hub image built with libpcap, or omit the filter")
	case err != nil:
		return value.CompiledFilter{}, filterRefusal(value.CompositionFilterRejected, path, "libpcap rejected the filter: "+bounded(err.Error(), 200))
	case f.LinkType != value.FilterLinkType || f.Snaplen != value.FilterSnaplen || len(f.Program) < 1:
		return value.CompiledFilter{}, filterRefusal(value.CompositionNoCompiler, path, "the filter compiler does not use the pinned link type")
	case len(f.Program) > value.MaxFilterInstructions:
		return value.CompiledFilter{}, filterRefusal(value.CompositionFilterRejected, path, fmt.Sprintf("the compiled filter has %d instructions; at most %d are allowed: narrow or simplify it", len(f.Program), value.MaxFilterInstructions))
	}
	return f, nil
}

func bounded(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
