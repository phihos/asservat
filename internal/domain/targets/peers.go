package targets

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Kubernetes packet peers (REQ-NET-002, ADR-283 PR 2). The target's region
// lists the referenced objects and resolves them with ResolvePeers into a
// frozen set of (UID, IP) members; the hub compiles their host prefixes into
// the reviewed filter. Resolution is an observation for review, never
// authority to attach to or read from a peer.

const (
	// MaxPeerEntries bounds the authored entries of one peer query.
	MaxPeerEntries = 16
	// MaxPeerEndpoints is the schema bound of maxEndpoints.
	MaxPeerEndpoints = 4096
	// MaxPeerMembers bounds one regional answer. The compiled filter bounds
	// (256 tokens, 256 instructions) admit far fewer host prefixes, and 256
	// members stay well inside one exchange frame.
	MaxPeerMembers = 256
	// MaxPeerSnapshotPods bounds the Pods one resolution reads.
	MaxPeerSnapshotPods = 1024
	// MaxPeerSnapshotSlices bounds the EndpointSlices one resolution reads.
	MaxPeerSnapshotSlices = 64
)

var (
	// ErrPeerLimit is a peer query resolving to more endpoints than its
	// maxEndpoints or MaxPeerMembers, or reading more objects than the
	// snapshot bounds. It is never truncated into a narrower set.
	ErrPeerLimit = errors.New("kubernetes peers exceed the endpoint limit")
	// ErrPeerUnsupported is a peer that has no qualified address identity:
	// an ExternalName or selectorless Service, a headless Service selected
	// by virtual IP, or a hostNetwork Pod (whose IP is its node's).
	ErrPeerUnsupported = errors.New("kubernetes peer kind unsupported")
	// ErrPeerMissing is a named peer that does not exist or is not visible.
	ErrPeerMissing = errors.New("kubernetes peer unavailable")
)

// PeerPodSelector selects Pods of one namespace by exact labels.
type PeerPodSelector struct {
	Namespace   string
	MatchLabels map[string]string
}

// PeerResourceRef names one Pod, Deployment, StatefulSet or Service. Only a
// Service has ServiceMode (backends, virtualIP or both) and ReadyOnly.
type PeerResourceRef struct {
	Kind, Namespace, Name string
	ServiceMode           string `json:",omitempty"`
	ReadyOnly             bool   `json:",omitempty"`
}

// PeerEntry is exactly one of Pods or Resource.
type PeerEntry struct {
	Pods     *PeerPodSelector `json:",omitempty"`
	Resource *PeerResourceRef `json:",omitempty"`
}

func (e PeerEntry) Namespace() string {
	switch {
	case e.Pods != nil:
		return e.Pods.Namespace
	case e.Resource != nil:
		return e.Resource.Namespace
	}
	return ""
}

// Bounded checks only the sizes of e, so a typed edit carries an invalid
// value to the compiler, which refuses it by path.
func (e PeerEntry) Bounded() bool {
	if (e.Pods == nil) == (e.Resource == nil) || len(e.Namespace()) > 63 {
		return false
	}
	if p := e.Pods; p != nil {
		if len(p.MatchLabels) > 16 {
			return false
		}
		for k, v := range p.MatchLabels {
			if len(k) > 317 || len(v) > 63 {
				return false
			}
		}
		return true
	}
	return len(e.Resource.Kind) <= 16 && len(e.Resource.Name) <= 253 && len(e.Resource.ServiceMode) <= 16
}

func (e PeerEntry) Valid() bool {
	if (e.Pods == nil) == (e.Resource == nil) || !dnsLabel(e.Namespace()) {
		return false
	}
	if p := e.Pods; p != nil {
		if len(p.MatchLabels) < 1 || len(p.MatchLabels) > 16 {
			return false
		}
		for k, v := range p.MatchLabels {
			if !labelKey(k) || !labelValue(v) || v == "" {
				return false
			}
		}
		return true
	}
	r := e.Resource
	if !dnsSubdomain(r.Name) {
		return false
	}
	switch r.Kind {
	case "Pod", "Deployment", "StatefulSet":
		return r.ServiceMode == "" && !r.ReadyOnly
	case "Service":
		return r.ServiceMode == "backends" || r.ServiceMode == "virtualIP" || r.ServiceMode == "both"
	}
	return false
}

func (e PeerEntry) equal(o PeerEntry) bool {
	switch {
	case e.Pods != nil && o.Pods != nil:
		if e.Pods.Namespace != o.Pods.Namespace || len(e.Pods.MatchLabels) != len(o.Pods.MatchLabels) {
			return false
		}
		for k, v := range e.Pods.MatchLabels {
			if w, ok := o.Pods.MatchLabels[k]; !ok || w != v {
				return false
			}
		}
		return true
	case e.Resource != nil && o.Resource != nil:
		return *e.Resource == *o.Resource
	}
	return false
}

// ClonePeerEntries deep-copies entries.
func ClonePeerEntries(in []PeerEntry) []PeerEntry {
	if in == nil {
		return nil
	}
	out := make([]PeerEntry, len(in))
	for i, e := range in {
		if e.Pods != nil {
			p := *e.Pods
			p.MatchLabels = make(map[string]string, len(e.Pods.MatchLabels))
			for k, v := range e.Pods.MatchLabels {
				p.MatchLabels[k] = v
			}
			out[i].Pods = &p
		}
		if e.Resource != nil {
			r := *e.Resource
			out[i].Resource = &r
		}
	}
	return out
}

// PeerRequest asks the target's region to resolve one action's Kubernetes
// peer entries in the target's own namespace (namespace confinement: the
// caller's eligibility covers that namespace only).
type PeerRequest struct {
	ClusterID    string
	Namespace    configuration.NamespaceRef
	Entries      []PeerEntry
	MaxEndpoints int
}

func (r PeerRequest) Valid() bool {
	if !authorization.UUID(r.ClusterID) || !dnsLabel(r.Namespace.Name) || !identity.Text(r.Namespace.UID, 64) || len(r.Entries) < 1 || len(r.Entries) > MaxPeerEntries || r.MaxEndpoints < 1 || r.MaxEndpoints > MaxPeerEndpoints {
		return false
	}
	for _, e := range r.Entries {
		if !e.Valid() || e.Namespace() != r.Namespace.Name {
			return false
		}
	}
	return true
}

// Equal reports whether two requests ask exactly the same query.
func (r PeerRequest) Equal(o PeerRequest) bool {
	return r.ClusterID == o.ClusterID && r.Namespace == o.Namespace && r.MaxEndpoints == o.MaxEndpoints && slices.EqualFunc(r.Entries, o.Entries, PeerEntry.equal)
}

// Limit is the effective member bound of r.
func (r PeerRequest) Limit() int { return min(r.MaxEndpoints, MaxPeerMembers) }

// PeerMember is one resolved address: a Pod IP (Kind Pod) or a Service
// cluster IP (Kind Service), with the UID of the object it belongs to.
type PeerMember struct {
	Kind, UID, IP string
}

func comparePeerMembers(a, b PeerMember) int {
	x, _ := netip.ParseAddr(a.IP)
	y, _ := netip.ParseAddr(b.IP)
	if c := x.Compare(y); c != 0 {
		return c
	}
	if c := strings.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	return strings.Compare(a.UID, b.UID)
}

// PeerResolution is the region's answer to Request: the sorted, unique
// members. ResolvedAt is set by the hub on receipt; it is the generation
// time recorded in the reviewed plan.
type PeerResolution struct {
	Request    PeerRequest
	Members    []PeerMember
	ResolvedAt time.Time `json:",omitzero"`
}

// Clone deep-copies a.
func (a PeerResolution) Clone() PeerResolution {
	a.Request.Entries = ClonePeerEntries(a.Request.Entries)
	a.Members = slices.Clone(a.Members)
	return a
}

// Answers reports whether a is a bounded, canonical answer to exactly r. An
// empty member list is a valid answer; the planner refuses it, since an
// empty peer set matches no traffic and never means all traffic.
func (a PeerResolution) Answers(r PeerRequest) bool {
	if !r.Valid() || !a.Request.Equal(r) || len(a.Members) > r.Limit() {
		return false
	}
	for i, m := range a.Members {
		addr, err := netip.ParseAddr(m.IP)
		if err != nil || !peerAddress(addr) || addr.String() != m.IP || (m.Kind != "Pod" && m.Kind != "Service") || !identity.Text(m.UID, 64) {
			return false
		}
		if i > 0 && comparePeerMembers(a.Members[i-1], m) >= 0 {
			return false
		}
	}
	return true
}

func peerAddress(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && !a.Is4In6() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast()
}

// PeerPod is the resolver's projection of one listed Pod.
type PeerPod struct {
	Name, UID                     string
	Labels                        map[string]string
	IPs                           []string
	ControllerKind, ControllerUID string
	Phase                         string
	HostNetwork                   bool
}

// PeerOwned is a listed ReplicaSet with its controller.
type PeerOwned struct {
	Name, UID                     string
	ControllerKind, ControllerUID string
}

// PeerWorkload is a read Deployment or StatefulSet.
type PeerWorkload struct{ Kind, Name, UID string }

// PeerService is a read Service.
type PeerService struct {
	Name, UID, Type string
	Selector        map[string]string
	ClusterIPs      []string
}

// PeerEndpointSlice is a listed EndpointSlice: its service-name label, its
// controlling Service UID and whether the endpointslice controller manages
// it. Slices that are not controller-managed are ignored.
type PeerEndpointSlice struct {
	ServiceName, ServiceUID string
	Managed                 bool
	AddressType             string
	Endpoints               []PeerEndpoint
}

// PeerEndpoint is one endpoint. Ready nil means unknown, which the API
// documents as ready. PodUID is its targetRef Pod UID ("" without one).
type PeerEndpoint struct {
	Addresses []string
	Ready     *bool
	PodUID    string
}

// PeerSnapshot is what the region listed for one request, all in the
// request's namespace. The order of every list is irrelevant.
type PeerSnapshot struct {
	Namespace      string
	Pods           []PeerPod
	ReplicaSets    []PeerOwned
	Workloads      []PeerWorkload
	Services       []PeerService
	EndpointSlices []PeerEndpointSlice
}

// ResolvePeers resolves r against one snapshot (pure). Entries are ORed:
//   - podSelector: Pods whose labels contain every matchLabels pair;
//   - Pod: that Pod;
//   - Deployment: Pods controlled by a ReplicaSet the Deployment controls;
//   - StatefulSet: Pods it controls;
//   - Service backends: endpoints of its controller-managed EndpointSlices
//     whose targetRef is a listed Pod matching the Service selector and whose
//     address is that Pod's IP of the slice's family; readyOnly drops
//     endpoints whose ready condition is false;
//   - Service virtualIP: its cluster IPs (a headless Service has none).
//
// Pods in phase Succeeded or Failed contribute nothing: their IPs may already
// belong to another Pod. Members are deduplicated by (kind, UID, IP) and
// sorted, so the result does not depend on LIST order.
func ResolvePeers(r PeerRequest, s PeerSnapshot) ([]PeerMember, error) {
	if !r.Valid() || s.Namespace != r.Namespace.Name {
		return nil, ErrInvalid
	}
	limit := r.Limit()
	pods := make(map[string]PeerPod, len(s.Pods))
	for _, p := range s.Pods {
		if !identity.Text(p.UID, 64) {
			return nil, ErrUnavailable
		}
		pods[p.UID] = p
	}
	set := map[PeerMember]bool{}
	add := func(kind, uid, ip string) error {
		a, err := netip.ParseAddr(ip)
		if err != nil || !peerAddress(a.Unmap()) {
			return ErrUnavailable
		}
		set[PeerMember{kind, uid, a.Unmap().String()}] = true
		if len(set) > limit {
			return ErrPeerLimit
		}
		return nil
	}
	podMembers := func(p PeerPod) error {
		if p.Phase == "Succeeded" || p.Phase == "Failed" {
			return nil
		}
		if p.HostNetwork {
			return ErrPeerUnsupported
		}
		for _, ip := range p.IPs {
			if err := add("Pod", p.UID, ip); err != nil {
				return err
			}
		}
		return nil
	}
	selected := func(match func(PeerPod) bool) error {
		for _, p := range s.Pods {
			if match(p) {
				if err := podMembers(p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, e := range r.Entries {
		var err error
		if e.Pods != nil {
			err = selected(func(p PeerPod) bool { return labelsMatch(e.Pods.MatchLabels, p.Labels) })
		} else {
			err = resolveResource(*e.Resource, s, pods, add, podMembers, selected)
		}
		if err != nil {
			return nil, err
		}
	}
	out := make([]PeerMember, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	slices.SortFunc(out, comparePeerMembers)
	return out, nil
}

func resolveResource(r PeerResourceRef, s PeerSnapshot, pods map[string]PeerPod, add func(kind, uid, ip string) error, podMembers func(PeerPod) error, selected func(func(PeerPod) bool) error) error {
	switch r.Kind {
	case "Pod":
		for _, p := range s.Pods {
			if p.Name == r.Name {
				return podMembers(p)
			}
		}
		return ErrPeerMissing
	case "Deployment", "StatefulSet":
		i := slices.IndexFunc(s.Workloads, func(w PeerWorkload) bool { return w.Kind == r.Kind && w.Name == r.Name })
		if i < 0 {
			return ErrPeerMissing
		}
		w := s.Workloads[i]
		if r.Kind == "StatefulSet" {
			return selected(func(p PeerPod) bool { return p.ControllerKind == "StatefulSet" && p.ControllerUID == w.UID })
		}
		owned := map[string]bool{}
		for _, rs := range s.ReplicaSets {
			if rs.ControllerKind == "Deployment" && rs.ControllerUID == w.UID {
				owned[rs.UID] = true
			}
		}
		return selected(func(p PeerPod) bool { return p.ControllerKind == "ReplicaSet" && owned[p.ControllerUID] })
	}
	i := slices.IndexFunc(s.Services, func(v PeerService) bool { return v.Name == r.Name })
	if i < 0 {
		return ErrPeerMissing
	}
	svc := s.Services[i]
	if svc.Type == "ExternalName" || len(svc.Selector) == 0 {
		return ErrPeerUnsupported
	}
	if r.ServiceMode != "virtualIP" {
		for _, slice := range s.EndpointSlices {
			if !slice.Managed || slice.ServiceName != svc.Name || slice.ServiceUID != svc.UID || (slice.AddressType != "IPv4" && slice.AddressType != "IPv6") {
				continue
			}
			for _, ep := range slice.Endpoints {
				p, ok := pods[ep.PodUID]
				if !ok || r.ReadyOnly && ep.Ready != nil && !*ep.Ready || !labelsMatch(svc.Selector, p.Labels) || p.Phase == "Succeeded" || p.Phase == "Failed" {
					continue
				}
				if p.HostNetwork {
					return ErrPeerUnsupported
				}
				for _, address := range ep.Addresses {
					a, err := netip.ParseAddr(address)
					if err != nil || a.Is4() != (slice.AddressType == "IPv4") || !slices.ContainsFunc(p.IPs, func(ip string) bool { b, err := netip.ParseAddr(ip); return err == nil && b.Unmap() == a.Unmap() }) {
						continue
					}
					if err := add("Pod", p.UID, address); err != nil {
						return err
					}
				}
			}
		}
	}
	if r.ServiceMode != "backends" {
		vips := 0
		for _, ip := range svc.ClusterIPs {
			if ip == "" || ip == "None" {
				continue
			}
			vips++
			if err := add("Service", svc.UID, ip); err != nil {
				return err
			}
		}
		if vips == 0 {
			return ErrPeerUnsupported
		}
	}
	return nil
}

func labelsMatch(want, have map[string]string) bool {
	for k, v := range want {
		if w, ok := have[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func dnsLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func dnsSubdomain(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !dnsLabel(part) {
			return false
		}
	}
	return true
}

// labelKey is a Kubernetes qualified name with an optional DNS prefix.
func labelKey(k string) bool {
	name := k
	if i := strings.LastIndexByte(k, '/'); i >= 0 {
		if !dnsSubdomain(k[:i]) {
			return false
		}
		name = k[i+1:]
	}
	return name != "" && labelValue(name)
}

// labelValue is at most 63 alphanumerics, '-', '_' or '.', beginning and
// ending with an alphanumeric (or empty).
func labelValue(v string) bool {
	if len(v) > 63 {
		return false
	}
	for i, c := range v {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && ((c != '-' && c != '_' && c != '.') || i == 0 || i == len(v)-1) {
			return false
		}
	}
	return true
}

// Membership verification (ADR-283 part 3). The region re-resolves a frozen
// peer query when a recording starts and once per second while it runs; the
// reviewed member set may not lose or change a member.

var (
	// ErrPeersChanged is a frozen membership that lost a member, whose
	// member changed its address, or whose address now belongs to another
	// object. The capture never continues with a different set.
	ErrPeersChanged = errors.New("kubernetes peer membership changed")
	// ErrPeersStale is a frozen membership no consistent resolution
	// confirmed within its freshness bound.
	ErrPeersStale = errors.New("kubernetes peer membership stale")
	// ErrPeerVerifierBusy is a region already verifying its maximum number
	// of running captures with Kubernetes peers.
	ErrPeerVerifierBusy = errors.New("kubernetes peer verifier capacity reached")
)

// PeerMembershipChanged reports whether current, a fresh resolution of the
// same query, no longer contains every frozen member, or assigns a frozen
// address to a different object. Members current adds are not captured
// (the reviewed filter is fixed), so they change nothing.
func PeerMembershipChanged(frozen, current []PeerMember) bool {
	have := make(map[PeerMember]bool, len(current))
	for _, m := range current {
		have[m] = true
	}
	byIP := make(map[string]PeerMember, len(frozen))
	for _, m := range frozen {
		if !have[m] {
			return true
		}
		byIP[m.IP] = m
	}
	for _, m := range current {
		if f, ok := byIP[m.IP]; ok && f != m {
			return true
		}
	}
	return false
}

// FrozenPeers is the connector's decoded view of a recording's frozen
// peers: the exact query, its reviewed resolution and the freshness bound.
type FrozenPeers struct {
	Resolution   PeerResolution
	MaxStaleness time.Duration
}
