package planning

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// peersWire is the packet-capture peers object of a typed packetPeers edit
// (ADR-283): cidrs entries first, then Kubernetes entries.
type peersWire struct {
	Entries      []peerEntryWire `json:"entries"`
	Protocol     string          `json:"protocol"`
	Ports        []int           `json:"ports,omitempty"`
	Resolution   string          `json:"resolution"`
	MaxEndpoints int             `json:"maxEndpoints"`
	MaxStaleness string          `json:"maxStaleness"`
}

type peerEntryWire struct {
	CIDRs       []string         `json:"cidrs,omitempty"`
	PodSelector *podSelectorWire `json:"podSelector,omitempty"`
	ResourceRef *resourceRefWire `json:"resourceRef,omitempty"`
}

type podSelectorWire struct {
	Namespace   string            `json:"namespace"`
	MatchLabels map[string]string `json:"matchLabels"`
}

type resourceRefWire struct {
	Kind        string  `json:"kind"`
	Namespace   string  `json:"namespace"`
	Name        string  `json:"name"`
	ServiceMode *string `json:"serviceMode,omitempty"`
	ReadyOnly   *bool   `json:"readyOnly,omitempty"`
}

func peersEditWire(p *value.PeerSelection) peersWire {
	out := peersWire{Protocol: p.Protocol, Ports: slices.Clone(p.Ports), Resolution: p.Resolution, MaxEndpoints: p.MaxEndpoints, MaxStaleness: p.MaxStaleness, Entries: []peerEntryWire{}}
	for _, c := range p.CIDRs {
		out.Entries = append(out.Entries, peerEntryWire{CIDRs: slices.Clone(c)})
	}
	for _, e := range p.Kubernetes {
		out.Entries = append(out.Entries, peerEntryToWire(e))
	}
	return out
}

func peerEntryToWire(e targets.PeerEntry) peerEntryWire {
	if e.Pods != nil {
		return peerEntryWire{PodSelector: &podSelectorWire{Namespace: e.Pods.Namespace, MatchLabels: maps.Clone(e.Pods.MatchLabels)}}
	}
	r := e.Resource
	w := &resourceRefWire{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}
	if r.Kind == "Service" {
		mode, ready := r.ServiceMode, r.ReadyOnly
		w.ServiceMode, w.ReadyOnly = &mode, &ready
	}
	return peerEntryWire{ResourceRef: w}
}

// PeerEntryFromWire strictly decodes one podSelector or resourceRef entry.
// It reports false for any other shape; Valid checks the values.
func PeerEntryFromWire(key string, raw json.RawMessage) (targets.PeerEntry, bool) {
	strictly := func(out any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(out) == nil
	}
	switch key {
	case "podSelector":
		var w podSelectorWire
		if !strictly(&w) {
			return targets.PeerEntry{}, false
		}
		return targets.PeerEntry{Pods: &targets.PeerPodSelector{Namespace: w.Namespace, MatchLabels: w.MatchLabels}}, true
	case "resourceRef":
		var w resourceRefWire
		if !strictly(&w) || (w.Kind == "Service") != (w.ServiceMode != nil && w.ReadyOnly != nil) || (w.Kind != "Service") && (w.ServiceMode != nil || w.ReadyOnly != nil) {
			return targets.PeerEntry{}, false
		}
		r := &targets.PeerResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
		if w.ServiceMode != nil {
			r.ServiceMode, r.ReadyOnly = *w.ServiceMode, *w.ReadyOnly
		}
		return targets.PeerEntry{Resource: r}, true
	}
	return targets.PeerEntry{}, false
}

// peerSet is the canonical resolved peer selection of one packet action:
// masked prefixes in address order, the transport and the sorted ports. For
// Kubernetes peers each resolved address is a host prefix.
type peerSet struct {
	Prefixes []string `json:"prefixes"`
	Protocol string   `json:"protocol"`
	Ports    []int    `json:"ports,omitempty"`
	// kubernetes is the frozen resolution provenance; it is recorded beside
	// the set, so peerSetDigest stays a digest of the compiled scope.
	kubernetes *kubernetesPeerRecord
}

// kubernetesPeerRecord is the frozen Kubernetes resolution of a plan (ADR-283
// PR 2): where and when it was resolved, how many (UID, IP) members it has
// and their digest. A later verifier re-resolves and compares the digest.
type kubernetesPeerRecord struct {
	ClusterID     string `json:"clusterID"`
	Namespace     string `json:"namespace"`
	NamespaceUID  string `json:"namespaceUID"`
	Endpoints     int    `json:"endpoints"`
	MembersDigest string `json:"membersDigest"`
	ResolvedAt    string `json:"resolvedAt"`
}

// peerSetRecord is the plan's provenance of a peer selection: the canonical
// set, its digest and the digest of the authored user filter it was
// intersected with (empty when there was none).
type peerSetRecord struct {
	peerSet
	Digest               string                `json:"peerSetDigest"`
	AuthoredFilterDigest string                `json:"authoredFilterDigest,omitempty"`
	Kubernetes           *kubernetesPeerRecord `json:"kubernetes,omitempty"`
}

const kubernetesPeersRemedy = "Kubernetes peers (podSelector, resourceRef) resolve only when previewing one packet capture of a resolved target; use cidrs entries (for example 10.0.0.0/24) here"

// KubernetesPeersAcceptance is why a plan with Kubernetes peers is not
// recordable yet (ADR-283 PR 2): without the runtime membership verifier a
// frozen set cannot be rechecked at arming.
const KubernetesPeersAcceptance = "Kubernetes peer capture needs the membership verifier of the next release; this plan can be previewed but not recorded. Use cidrs peers to record now."

// peerContext is the resolved target a plan's Kubernetes peers resolve in,
// and the region's resolutions available to the compiler. nil refuses
// Kubernetes peers.
type peerContext struct {
	clusterID string
	namespace cfg.NamespaceRef
	resolved  []targets.PeerResolution
	now       time.Time
	used      map[int]bool
}

// PeerResolutionNeeded reports that a plan has Kubernetes peers whose
// region resolution is not in the input. The caller asks the target's region
// for Request and compiles again with the answer; it is never a refusal by
// itself.
type PeerResolutionNeeded struct {
	Request targets.PeerRequest
	Path    string
}

func (e PeerResolutionNeeded) Error() string {
	return "kubernetes peers at " + e.Path + " need the target region's resolution"
}

// PeerResolutionRefusal maps a failed region resolution of needed to the
// composition refusal at its path; any other error is returned unchanged.
func PeerResolutionRefusal(needed PeerResolutionNeeded, err error) error {
	switch {
	case errors.Is(err, targets.ErrPeerLimit):
		return refuse(value.CompositionInvalid, needed.Path+".maxEndpoints", fmt.Sprintf("the Kubernetes peers resolve to more than %d endpoints; select fewer peers, raise maxEndpoints or use cidrs entries", needed.Request.Limit()))
	case errors.Is(err, targets.ErrPeerUnsupported):
		return refuse(value.CompositionRecorderUnavailable, needed.Path+".entries", "a peer has no qualified address identity: ExternalName and selectorless Services, virtual IPs of headless Services and hostNetwork Pods are not supported; select other peers or use cidrs entries")
	case errors.Is(err, targets.ErrPeerMissing):
		return refuse(value.CompositionInvalid, needed.Path+".entries", "a referenced peer is unavailable in the target's namespace")
	}
	return err
}

// packetPeers parses one action's peers. The whole-pod default (one frozen
// entry of exactly 0.0.0.0/0 and ::/0 for any protocol) returns nil, so it
// adds no filter and keeps existing plans byte-identical. A cidrs selection
// returns its canonical set; Kubernetes entries add the host prefixes of the
// region's frozen resolution. Anything else is refused, never widened to all
// traffic.
func packetPeers(path string, raw json.RawMessage, pc *peerContext) (*peerSet, error) {
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
	var kubernetes []targets.PeerEntry
	for i, entry := range p.Entries {
		entryPath := pathf("%s.entries[%d]", path, i)
		if len(entry) != 1 {
			return nil, refuse(value.CompositionInvalid, entryPath, "a peer entry is exactly one of cidrs, podSelector or resourceRef")
		}
		if _, ok := entry["cidrs"]; ok {
			continue
		}
		for key, v := range entry {
			e, ok := PeerEntryFromWire(key, v)
			if !ok || !e.Valid() {
				return nil, refuse(value.CompositionInvalid, entryPath, "a podSelector names a namespace and 1 to 16 labels; a resourceRef names a Pod, Deployment, StatefulSet or Service (a Service also serviceMode and readyOnly)")
			}
			if pc == nil {
				return nil, refuse(value.CompositionRecorderUnavailable, entryPath, kubernetesPeersRemedy)
			}
			if e.Namespace() != pc.namespace.Name {
				return nil, refuse(value.CompositionInvalid, entryPath+"."+key+".namespace", "Kubernetes peers must be in the target's namespace "+strconv.Quote(pc.namespace.Name)+"; use cidrs entries for other peers")
			}
			kubernetes = append(kubernetes, e)
		}
	}
	if len(p.Entries) == 0 {
		return nil, refuse(value.CompositionInvalid, path+".entries", "an empty peer set matches no traffic; add a cidrs, podSelector or resourceRef entry")
	}
	if len(p.Entries) > targets.MaxPeerEntries {
		return nil, refuse(value.CompositionInvalid, path+".entries", "at most 16 peer entries")
	}
	// ADR-283: a CIDR selection has no membership to follow, so follow and
	// frozen resolve identically. Kubernetes membership is frozen at preview;
	// follow waits for the measured LIST load (open item 7).
	if p.Resolution != "frozen" && p.Resolution != "follow" {
		return nil, refuse(value.CompositionInvalid, path+".resolution", "resolution is frozen or follow")
	}
	if len(kubernetes) > 0 && p.Resolution != "frozen" {
		return nil, refuse(value.CompositionRecorderUnavailable, path+".resolution", "Kubernetes peers resolve frozen in this release; follow is not available yet")
	}
	if p.MaxEndpoints < 1 || p.MaxEndpoints > targets.MaxPeerEndpoints {
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
		if _, ok := entry["cidrs"]; !ok {
			continue
		}
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
	if len(kubernetes) > 0 {
		request := targets.PeerRequest{ClusterID: pc.clusterID, Namespace: pc.namespace, Entries: kubernetes, MaxEndpoints: p.MaxEndpoints}
		r, ok := pc.resolution(request)
		if !ok {
			return nil, PeerResolutionNeeded{Request: request, Path: path}
		}
		if len(r.Members) == 0 {
			return nil, refuse(value.CompositionInvalid, path+".entries", "the Kubernetes peers resolve to no endpoints; an empty peer set matches no traffic")
		}
		for _, m := range r.Members {
			addr := netip.MustParseAddr(m.IP)
			if prefix := netip.PrefixFrom(addr, addr.BitLen()); !slices.Contains(prefixes, prefix) {
				prefixes = append(prefixes, prefix)
			}
		}
		b, err := json.Marshal(r.Members)
		if err != nil {
			return nil, value.ErrInvalid
		}
		_, digest, err := canonical(b)
		if err != nil {
			return nil, value.ErrInvalid
		}
		set.kubernetes = &kubernetesPeerRecord{ClusterID: pc.clusterID, Namespace: pc.namespace.Name, NamespaceUID: pc.namespace.UID, Endpoints: len(r.Members), MembersDigest: hexDigest(digest), ResolvedAt: r.ResolvedAt.UTC().Format(time.RFC3339Nano)}
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

// resolution returns the input's answer to exactly request and marks it
// used. A resolution from the future or for another query is not used.
func (pc *peerContext) resolution(request targets.PeerRequest) (targets.PeerResolution, bool) {
	for i, r := range pc.resolved {
		if r.Answers(request) && !r.ResolvedAt.IsZero() && !r.ResolvedAt.After(pc.now) {
			pc.used[i] = true
			return r, true
		}
	}
	return targets.PeerResolution{}, false
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
	r := &peerSetRecord{peerSet: *s, Digest: hexDigest(d), Kubernetes: s.kubernetes}
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
