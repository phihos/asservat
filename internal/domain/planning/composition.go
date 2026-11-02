package planning

import (
	"strings"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/targets"
)

// Bounds of the authored profile composition (specs/contracts/capture-composition.schema.json).
const (
	MaxCompositionComponents = 8
	MaxComponentEdits        = 32
	MaxCompositionBytes      = 1 << 40
)

// ProfileRef names one immutable capture profile version. It carries no
// precedence: builtin, organization and namespace references never shadow each other.
type ProfileRef struct {
	Catalog, Name, Version string
}

func (r ProfileRef) Valid() bool {
	switch r.Catalog {
	case "builtin", "organization", "namespace":
	default:
		return false
	}
	return lowerName(r.Name, 63) && len(r.Version) >= 2 && len(r.Version) <= 32 && r.Version[0] == 'v' && r.Version[1] != '0' && digits(r.Version[1:])
}

// RingSettings is the typed value of a packetRing or syscallRing edit.
type RingSettings struct {
	MaxAge                 string
	MaxBytes, SegmentBytes int64
	MaxSegments            int
	Medium                 string
	StorageProfileRef      string `json:",omitempty"`
}

// SyscallSelection is the typed value of a syscallFilter edit.
type SyscallSelection struct {
	Mode  string
	Names []string `json:",omitempty"`
}

// PeerSelection is the typed value of a packetPeers edit (ADR-283): each
// CIDRs entry lists prefixes and each Kubernetes entry selects Pods or names
// one resource; all entries are ORed. The wire form lists the cidrs entries
// first, then the Kubernetes entries, each in authored order.
type PeerSelection struct {
	CIDRs        [][]string
	Kubernetes   []targets.PeerEntry `json:",omitempty"`
	Protocol     string
	Ports        []int `json:",omitempty"`
	Resolution   string
	MaxEndpoints int
	MaxStaleness string
}

// ProfileEdit is one typed override of an exposed profile field. Exactly the
// member registered for its field carries the literal value; there is no
// interpolation, patch or expression language. Unmodeled marks a registered
// field whose value type this release does not accept, so the compiler can
// refuse it with its field path instead of a generic wire error. TextSet
// marks a text field sent as the empty string, so the field's own validator
// answers with its remedy instead of a generic malformed-composition error.
type ProfileEdit struct {
	ActionID, Field string
	Text            string            `json:",omitempty"`
	Number          int64             `json:",omitempty"`
	Ring            *RingSettings     `json:",omitempty"`
	Syscalls        *SyscallSelection `json:",omitempty"`
	Peers           *PeerSelection    `json:",omitempty"`
	Unmodeled       bool              `json:",omitempty"`
	TextSet         bool              `json:",omitempty"`
}

// ProfileComponent selects one profile version and its edits.
type ProfileComponent struct {
	ID      string
	Profile ProfileRef
	Edits   []ProfileEdit `json:",omitempty"`
}

// ProfileComposition is the authored third selection form of preview_capture.
// Only bounds are checked here; the planning compiler resolves definitions,
// applies the edits and validates the resulting plan as a whole.
type ProfileComposition struct {
	Components    []ProfileComponent
	MaxTotalBytes int64
	MaxDuration   string
	// Resolved holds the organization and namespace profile versions the
	// caller read for this compilation (one bounded read per preview, one per
	// start). It is never authored or persisted: every compilation reads the
	// current published versions again, so a disabled or deleted version
	// cannot authorize a new start from a stored preview or history.
	Resolved []CatalogProfile `json:"-"`
}

// CatalogProfile is one published CaptureProfile version (REQ-CPR-001): its
// immutable document {name, version, definition}, its current availability
// and its source identity. The compiler verifies the document and pins its
// digest; the source identity enters the resolved provenance.
type CatalogProfile struct {
	Ref                                            ProfileRef
	SourceClusterID, SourceNamespaceUID, SourceUID string
	Document                                       []byte
	Enabled, Deprecated                            bool
}

func (c *ProfileComposition) Valid() bool {
	if c == nil || len(c.Components) < 1 || len(c.Components) > MaxCompositionComponents || c.MaxTotalBytes < 1 || c.MaxTotalBytes > MaxCompositionBytes || !positiveDuration(c.MaxDuration) {
		return false
	}
	seen := map[string]bool{}
	for _, component := range c.Components {
		if !lowerName(component.ID, 24) || seen[component.ID] || !component.Profile.Valid() || len(component.Edits) > MaxComponentEdits {
			return false
		}
		seen[component.ID] = true
		for _, e := range component.Edits {
			if !e.valid() {
				return false
			}
		}
	}
	return true
}

func (e ProfileEdit) valid() bool {
	if e.ActionID == "" || len(e.ActionID) > 63 || e.Field == "" || len(e.Field) > 32 || len(e.Text) > 4096 || !utf8.ValidString(e.Text) || e.Number < 0 {
		return false
	}
	set := 0
	for _, present := range []bool{e.Text != "" || e.TextSet, e.Number != 0, e.Ring != nil, e.Syscalls != nil, e.Peers != nil, e.Unmodeled} {
		if present {
			set++
		}
	}
	if set != 1 {
		return false
	}
	if e.Ring != nil && (len(e.Ring.MaxAge) > 16 || len(e.Ring.Medium) > 16 || len(e.Ring.StorageProfileRef) > 63) {
		return false
	}
	if p := e.Peers; p != nil {
		if len(p.CIDRs)+len(p.Kubernetes) > 16 || len(p.Ports) > 32 || len(p.Protocol) > 16 || len(p.Resolution) > 16 || len(p.MaxStaleness) > 16 {
			return false
		}
		for _, entry := range p.Kubernetes {
			if !entry.Bounded() {
				return false
			}
		}
		for _, entry := range p.CIDRs {
			if len(entry) > 128 {
				return false
			}
			for _, c := range entry {
				if c == "" || len(c) > 64 {
					return false
				}
			}
		}
	}
	if e.Syscalls != nil {
		if len(e.Syscalls.Mode) > 16 || len(e.Syscalls.Names) > 128 {
			return false
		}
		for _, n := range e.Syscalls.Names {
			if n == "" || len(n) > 64 {
				return false
			}
		}
	}
	return true
}

func (c *ProfileComposition) clone() *ProfileComposition {
	if c == nil {
		return nil
	}
	out := *c
	out.Components = make([]ProfileComponent, len(c.Components))
	for i, component := range c.Components {
		component.Edits = append([]ProfileEdit(nil), component.Edits...)
		for j, e := range component.Edits {
			if e.Ring != nil {
				r := *e.Ring
				component.Edits[j].Ring = &r
			}
			if e.Syscalls != nil {
				s := *e.Syscalls
				s.Names = append([]string(nil), s.Names...)
				component.Edits[j].Syscalls = &s
			}
			if e.Peers != nil {
				p := *e.Peers
				p.CIDRs = make([][]string, len(e.Peers.CIDRs))
				for k, entry := range e.Peers.CIDRs {
					p.CIDRs[k] = append([]string(nil), entry...)
				}
				p.Ports = append([]int(nil), e.Peers.Ports...)
				p.Kubernetes = targets.ClonePeerEntries(e.Peers.Kubernetes)
				component.Edits[j].Peers = &p
			}
		}
		out.Components[i] = component
	}
	if c.Resolved != nil {
		out.Resolved = make([]CatalogProfile, len(c.Resolved))
		for i, r := range c.Resolved {
			r.Document = append([]byte(nil), r.Document...)
			out.Resolved[i] = r
		}
	}
	return &out
}

// Clone returns an independent copy for callers outside this package.
func (c *ProfileComposition) Clone() *ProfileComposition { return c.clone() }

func lowerName(s string, max int) bool {
	if s == "" || len(s) > max || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// positiveDuration matches the common contract duration ^[1-9][0-9]*(ms|s|m|h|d)$.
func positiveDuration(s string) bool {
	if len(s) < 2 || len(s) > 16 || s[0] < '1' || s[0] > '9' {
		return false
	}
	for _, unit := range []string{"ms", "s", "m", "h", "d"} {
		if number, ok := strings.CutSuffix(s, unit); ok && digits(number) {
			return true
		}
	}
	return false
}
