package planning

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// peersWire is the packet-capture peers object with only cidrs entries
// (ADR-283). Kubernetes entries are refused before this shape is used.
type peersWire struct {
	Entries      []peerEntryWire `json:"entries"`
	Protocol     string          `json:"protocol"`
	Ports        []int           `json:"ports,omitempty"`
	Resolution   string          `json:"resolution"`
	MaxEndpoints int             `json:"maxEndpoints"`
	MaxStaleness string          `json:"maxStaleness"`
}

type peerEntryWire struct {
	CIDRs []string `json:"cidrs"`
}

func peersEditWire(p *value.PeerSelection) peersWire {
	out := peersWire{Protocol: p.Protocol, Ports: slices.Clone(p.Ports), Resolution: p.Resolution, MaxEndpoints: p.MaxEndpoints, MaxStaleness: p.MaxStaleness, Entries: []peerEntryWire{}}
	for _, c := range p.CIDRs {
		out.Entries = append(out.Entries, peerEntryWire{slices.Clone(c)})
	}
	return out
}

// peerSet is the canonical resolved CIDR selection of one packet action:
// masked prefixes in address order, the transport and the sorted ports.
type peerSet struct {
	Prefixes []string `json:"prefixes"`
	Protocol string   `json:"protocol"`
	Ports    []int    `json:"ports,omitempty"`
}

// peerSetRecord is the plan's provenance of a CIDR peer selection: the
// canonical set, its digest and the digest of the authored user filter it
// was intersected with (empty when there was none).
type peerSetRecord struct {
	peerSet
	Digest               string `json:"peerSetDigest"`
	AuthoredFilterDigest string `json:"authoredFilterDigest,omitempty"`
}

const kubernetesPeersRemedy = "Kubernetes peer selection (podSelector, resourceRef) follows in a later release; use cidrs entries (for example 10.0.0.0/24) or narrow traffic with packetFilter"

// packetPeers parses one action's peers. The whole-pod default (one frozen
// entry of exactly 0.0.0.0/0 and ::/0 for any protocol) returns nil, so it
// adds no filter and keeps existing plans byte-identical. A cidrs-only
// selection returns its canonical set; anything else is refused, never
// widened to all traffic.
func packetPeers(path string, raw json.RawMessage) (*peerSet, error) {
	if wholePodPeers(raw) {
		return nil, nil
	}
	var p struct {
		Entries      []map[string]json.RawMessage `json:"entries"`
		Protocol     string                       `json:"protocol"`
		Ports        []int                        `json:"ports"`
		Resolution   string                       `json:"resolution"`
		MaxEndpoints int                          `json:"maxEndpoints"`
		MaxStaleness string                       `json:"maxStaleness"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) == 0 || d.Decode(&p) != nil {
		return nil, refuse(value.CompositionInvalid, path, "peers take entries, protocol, resolution, maxEndpoints and maxStaleness")
	}
	for i, entry := range p.Entries {
		if _, ok := entry["cidrs"]; !ok || len(entry) != 1 {
			return nil, refuse(value.CompositionRecorderUnavailable, pathf("%s.entries[%d]", path, i), kubernetesPeersRemedy)
		}
	}
	if len(p.Entries) == 0 {
		return nil, refuse(value.CompositionInvalid, path+".entries", "an empty peer set matches no traffic; add a cidrs entry")
	}
	if len(p.Entries) > 16 {
		return nil, refuse(value.CompositionInvalid, path+".entries", "at most 16 peer entries")
	}
	// ADR-283: a CIDR selection has no membership to follow, so follow and
	// frozen resolve identically.
	if p.Resolution != "frozen" && p.Resolution != "follow" {
		return nil, refuse(value.CompositionInvalid, path+".resolution", "resolution is frozen or follow")
	}
	if p.MaxEndpoints < 1 || p.MaxEndpoints > 4096 {
		return nil, refuse(value.CompositionInvalid, path+".maxEndpoints", "maxEndpoints is 1 to 4,096")
	}
	if _, ok := durationValue(p.MaxStaleness, false); !ok {
		return nil, refuse(value.CompositionInvalid, path+".maxStaleness", "maxStaleness is a positive duration")
	}
	set := &peerSet{Protocol: p.Protocol}
	switch p.Protocol {
	case "any", "tcp", "udp":
	case "icmp":
		if len(p.Ports) != 0 {
			return nil, refuse(value.CompositionInvalid, path+".ports", "ICMP has no ports; remove ports or select tcp, udp or any")
		}
	default:
		return nil, refuse(value.CompositionInvalid, path+".protocol", "the peer protocol is any, tcp, udp or icmp")
	}
	if len(p.Ports) > 32 {
		return nil, refuse(value.CompositionInvalid, path+".ports", "at most 32 peer ports")
	}
	for _, port := range p.Ports {
		if port < 1 || port > 65535 || slices.Contains(set.Ports, port) {
			return nil, refuse(value.CompositionInvalid, path+".ports", "peer ports are unique numbers from 1 to 65535")
		}
		set.Ports = append(set.Ports, port)
	}
	slices.Sort(set.Ports)
	var prefixes []netip.Prefix
	for i, entry := range p.Entries {
		var cidrs []string
		entryPath := pathf("%s.entries[%d].cidrs", path, i)
		if json.Unmarshal(entry["cidrs"], &cidrs) != nil || len(cidrs) < 1 || len(cidrs) > 128 {
			return nil, refuse(value.CompositionInvalid, entryPath, "a cidrs entry lists 1 to 128 prefixes")
		}
		for _, c := range cidrs {
			prefix, err := netip.ParsePrefix(c)
			if err != nil {
				addr, aerr := netip.ParseAddr(c)
				if aerr != nil || addr.Zone() != "" {
					return nil, refuse(value.CompositionInvalid, entryPath, fmt.Sprintf("%q is not an IP address or CIDR prefix; names are never resolved", bounded(c, 64)))
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			prefix = prefix.Masked()
			if slices.Contains(prefixes, prefix) {
				return nil, refuse(value.CompositionInvalid, entryPath, fmt.Sprintf("the prefix %s is selected twice", prefix))
			}
			prefixes = append(prefixes, prefix)
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	for _, prefix := range prefixes {
		set.Prefixes = append(set.Prefixes, prefix.String())
	}
	return set, nil
}

// expression renders the peer selection in pcap-filter syntax and intersects
// it with the normalized user filter. Both sides are parenthesized, and the
// user filter's brackets were checked to balance, so an `or host ...` in it
// can never widen the peer scope (SC-NET-001).
func (s *peerSet) expression(user string) string {
	nets := make([]string, len(s.Prefixes))
	for i, p := range s.Prefixes {
		nets[i] = "net " + p
	}
	parts := []string{"(" + strings.Join(nets, " or ") + ")"}
	switch s.Protocol {
	case "tcp", "udp":
		parts = append(parts, s.Protocol)
	case "icmp":
		parts = append(parts, "(icmp or icmp6)")
	}
	if len(s.Ports) > 0 {
		ports := make([]string, len(s.Ports))
		for i, p := range s.Ports {
			ports[i] = "port " + strconv.Itoa(p)
		}
		parts = append(parts, "("+strings.Join(ports, " or ")+")")
	}
	peers := strings.Join(parts, " and ")
	if user == "" {
		return peers
	}
	return "(" + peers + ") and (" + user + ")"
}

func (s *peerSet) record(user string) *peerSetRecord {
	b, _ := json.Marshal(s)
	_, d, _ := canonical(b)
	r := &peerSetRecord{peerSet: *s, Digest: hexDigest(d)}
	if user != "" {
		r.AuthoredFilterDigest = hexDigest(artifact.Digest(sha256.Sum256([]byte(user))))
	}
	return r
}

// balancedFilter reports whether the expression's parentheses and brackets
// nest properly, so wrapping it in parentheses keeps it one operand.
func balancedFilter(expression string) bool {
	var stack []byte
	for i := 0; i < len(expression); i++ {
		switch c := expression[i]; c {
		case '(', '[':
			stack = append(stack, c)
		case ')', ']':
			open := byte('(')
			if c == ']' {
				open = '['
			}
			if len(stack) == 0 || stack[len(stack)-1] != open {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}
	return len(stack) == 0
}
