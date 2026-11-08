// Package live contains the closed approved live projection values. These
// structural values never grant source, viewer or disclosure authority.
package live

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	Packet         = "packetMetadata"
	HTTP           = "httpHeaders"
	Syscall        = "syscallMetadata"
	MaxSources     = 16
	MaxRows        = 100
	MaxBufferRows  = 500
	MaxBufferBytes = 1 << 20
	MaxBatchBytes  = 20 << 10 // Reserve the existing 24KiB public envelope.
	RowAge         = 30 * time.Second
	ReplayAge      = 5 * time.Second
	IdleAge        = 30 * time.Second
)

var (
	ErrInvalid     = errors.New("live: invalid request")
	ErrDenied      = errors.New("live: unavailable or denied")
	ErrConflict    = errors.New("live: revision or idempotency conflict")
	ErrCapacity    = errors.New("live: capacity unavailable")
	ErrUnavailable = errors.New("live: projection unavailable")
	// ErrTransient marks a read that failed on a temporary source/status miss:
	// nothing was disclosed and the view stays open for the next read.
	ErrTransient = errors.New("live: temporarily unavailable")
	// ErrEnded marks a finite source that has ended; the view ends normally.
	ErrEnded = errors.New("live: source ended")
)

// Diagnostic returns fixed words for a refusal: its sentinel class plus the
// first producer-owned location markers (for example "service:442"). It never
// includes identifiers, inputs or dependency error text, so refusal logs stay
// free of user data and cannot become a decision oracle beyond the class.
func Diagnostic(err error) string {
	class := "other"
	for _, c := range []struct {
		err  error
		word string
	}{{ErrTransient, "transient"}, {ErrEnded, "ended"}, {ErrCapacity, "capacity"}, {ErrConflict, "conflict"}, {ErrInvalid, "invalid"}, {ErrDenied, "denied"}, {ErrUnavailable, "unavailable"}} {
		if errors.Is(err, c.err) {
			class = c.word
			break
		}
	}
	if err == nil {
		return class
	}
	// Nested producer markers (outer first) name the refusing stage chain.
	markers := 0
	for _, word := range strings.Fields(err.Error()) {
		word = strings.TrimRight(word, ":,;)")
		prefix, suffix, ok := strings.Cut(word, ":")
		if ok && slices.Contains(diagnosticPrefixes, prefix) && suffix != "" && len(suffix) <= 24 && strings.Trim(suffix, "0123456789abcdefghijklmnopqrstuvwxyz-") == "" {
			if markers == 0 {
				class += " at"
			}
			class += " " + word
			if markers++; markers == 4 {
				break
			}
		}
	}
	return class
}

var diagnosticPrefixes = []string{"service", "live_environment", "handles", "cursor", "live_batch", "live_catalog", "live_manual_sources", "live_owner", "live_owner_codec", "live_owner_router", "live_projection_reader", "live_sources", "live_watch", "public_live"}

func Projection(s string) bool { return s == Packet || s == HTTP || s == Syscall }
func Terminal(s string) bool   { return s != "Active" && s != "Paused" && s != "Disconnected" }

type Predicate struct {
	Field string          `json:"field"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value"`
}
type Filter struct {
	All []Predicate `json:"all"`
}

func (f Filter) Valid(projection string) bool {
	if !Projection(projection) || len(f.All) > 16 {
		return false
	}
	for _, p := range f.All {
		if p.Op != "eq" && p.Op != "neq" && p.Op != "gte" && p.Op != "lte" {
			return false
		}
		allowed := (projection == Packet && slices.Contains([]string{"protocol", "peer_uid", "remote_ip", "port", "pid"}, p.Field)) || (projection == HTTP && slices.Contains([]string{"method", "status", "peer_uid"}, p.Field)) || (projection == Syscall && slices.Contains([]string{"syscall", "error", "pid"}, p.Field))
		if !allowed {
			return false
		}
		switch p.Field {
		case "port", "pid", "status":
			var value *int
			if json.Unmarshal(p.Value, &value) != nil || value == nil || *value < 0 {
				return false
			}
			n := *value
			cap := 65535
			if p.Field == "pid" {
				cap = 4194304
			}
			if p.Field == "status" {
				cap = 599
			}
			if n > cap {
				return false
			}
		case "error":
			var b *bool
			if p.Op != "eq" || json.Unmarshal(p.Value, &b) != nil || b == nil {
				return false
			}
		default:
			var s string
			if p.Op != "eq" && p.Op != "neq" || json.Unmarshal(p.Value, &s) != nil || !identity.Text(s, 128) || s == "" {
				return false
			}
			if p.Field == "remote_ip" {
				if _, err := netip.ParseAddr(s); err != nil {
					return false
				}
			}
		}
	}
	return true
}

// Row has one closed field union. Raw packet bytes, syscall arguments, filenames
// and arbitrary dynamic keys cannot cross this boundary.
type Row struct {
	ID               string         `json:"row_id"`
	SourceID         string         `json:"source_session_id"`
	Sequence         uint64         `json:"source_sequence"`
	ObservedAt       time.Time      `json:"observed_at"`
	ReceivedAt       time.Time      `json:"received_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	ClockUncertainty int            `json:"clock_uncertainty_ms"`
	Generation       int64          `json:"filter_generation"`
	Projection       string         `json:"projection"`
	PodUID           string         `json:"pod_uid"`
	Packet           *PacketFields  `json:"-"`
	HTTP             *HTTPFields    `json:"-"`
	Syscall          *SyscallFields `json:"-"`
}
type PacketFields struct {
	Protocol   string  `json:"protocol"`
	PeerUID    *string `json:"peer_uid"`
	RemoteIP   string  `json:"remote_ip"`
	RemotePort int     `json:"remote_port"`
	Direction  string  `json:"direction"`
	WireBytes  int     `json:"wire_bytes"`
	PID        *int    `json:"pid"`
}
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type HTTPFields struct {
	Method   string   `json:"method"`
	Status   *int     `json:"status"`
	PeerUID  *string  `json:"peer_uid"`
	Headers  []Header `json:"headers"`
	Pairing  string   `json:"pairing"`
	Duration *int     `json:"duration_ms"`
}
type SyscallFields struct {
	PID      int    `json:"pid"`
	Name     string `json:"syscall"`
	Error    bool   `json:"error"`
	Errno    *int   `json:"errno"`
	Duration *int64 `json:"duration_ns"`
	Paired   bool   `json:"paired"`
}

func (r Row) MarshalJSON() ([]byte, error) {
	type base Row
	var fields any
	switch r.Projection {
	case Packet:
		fields = r.Packet
	case HTTP:
		fields = r.HTTP
	case Syscall:
		fields = r.Syscall
	}
	return json.Marshal(struct {
		base
		Fields any `json:"fields"`
	}{base(r), fields})
}
func (r Row) Valid(now time.Time) bool {
	if !authorization.UUID(r.SourceID) || !identity.Text(r.ID, 180) || r.ID == "" || r.Sequence < 1 || r.Sequence > 9007199254740991 || !identity.Text(r.PodUID, 64) || r.PodUID == "" || r.ObservedAt.IsZero() || r.ReceivedAt.Before(r.ObservedAt) || r.ReceivedAt.After(now) || !now.Before(r.ExpiresAt) || r.ExpiresAt.After(r.ObservedAt.Add(RowAge)) || r.ClockUncertainty < 0 || r.ClockUncertainty > 5000 || r.Generation < 0 || r.Generation > 1000000000 {
		return false
	}
	switch r.Projection {
	case Packet:
		p := r.Packet
		return p != nil && r.HTTP == nil && r.Syscall == nil && slices.Contains([]string{"TCP", "UDP", "ICMP", "Other", "Unknown"}, p.Protocol) && validIP(p.RemoteIP) && p.RemotePort >= 0 && p.RemotePort <= 65535 && slices.Contains([]string{"ingress", "egress", "unknown"}, p.Direction) && p.WireBytes >= 0 && p.WireBytes <= 1048576 && (p.PID == nil || *p.PID >= 1 && *p.PID <= 4194304) && optionalText(p.PeerUID, 64)
	case HTTP:
		p := r.HTTP
		if p == nil || r.Packet != nil || r.Syscall != nil || !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "OTHER"}, p.Method) || p.Status != nil && (*p.Status < 100 || *p.Status > 599) || !optionalText(p.PeerUID, 64) || p.Headers == nil || len(p.Headers) > 2 || !slices.Contains([]string{"request", "response", "paired"}, p.Pairing) || p.Duration != nil && (*p.Duration < 0 || *p.Duration > 60000) {
			return false
		}
		for n, h := range p.Headers {
			if !slices.Contains([]string{"content-type", "content-length"}, h.Name) || n > 0 && p.Headers[0].Name == h.Name || !identity.Text(h.Value, 256) || h.Value == "" {
				return false
			}
		}
		return true
	case Syscall:
		p := r.Syscall
		return p != nil && r.Packet == nil && r.HTTP == nil && p.PID >= 1 && p.PID <= 4194304 && identity.Text(p.Name, 64) && p.Name != "" && (p.Errno == nil || *p.Errno >= 0 && *p.Errno <= 4095) && (p.Duration == nil || *p.Duration >= 0 && *p.Duration <= 1000000000000) && (p.Paired || p.Duration == nil)
	}
	return false
}
func validIP(s string) bool              { _, e := netip.ParseAddr(s); return e == nil }
func optionalText(s *string, n int) bool { return s == nil || *s != "" && identity.Text(*s, n) }
func (r Row) Bytes() int                 { b, _ := json.Marshal(r); return len(b) }
func (r Row) Clone() Row {
	b, _ := json.Marshal(r)
	var raw struct {
		Fields json.RawMessage `json:"fields"`
	}
	_ = json.Unmarshal(b, &raw)
	out := r
	out.Packet = nil
	out.HTTP = nil
	out.Syscall = nil
	switch r.Projection {
	case Packet:
		out.Packet = new(PacketFields)
		_ = json.Unmarshal(raw.Fields, out.Packet)
	case HTTP:
		out.HTTP = new(HTTPFields)
		_ = json.Unmarshal(raw.Fields, out.HTTP)
	case Syscall:
		out.Syscall = new(SyscallFields)
		_ = json.Unmarshal(raw.Fields, out.Syscall)
	}
	return out
}
func (f Filter) Match(r Row) bool {
	if !f.Valid(r.Projection) {
		return false
	}
	for _, p := range f.All {
		var actual any
		if v := r.Packet; v != nil {
			switch p.Field {
			case "protocol":
				actual = v.Protocol
			case "peer_uid":
				if v.PeerUID != nil {
					actual = *v.PeerUID
				}
			case "remote_ip":
				actual = v.RemoteIP
			case "port":
				actual = v.RemotePort
			case "pid":
				if v.PID != nil {
					actual = *v.PID
				}
			}
		}
		if v := r.HTTP; v != nil {
			switch p.Field {
			case "method":
				actual = v.Method
			case "peer_uid":
				if v.PeerUID != nil {
					actual = *v.PeerUID
				}
			case "status":
				if v.Status != nil {
					actual = *v.Status
				}
			}
		}
		if v := r.Syscall; v != nil {
			switch p.Field {
			case "syscall":
				actual = v.Name
			case "error":
				actual = v.Error
			case "pid":
				actual = v.PID
			}
		}
		// Unknown is never used as a predicate oracle, including !=.
		if actual == nil {
			return false
		}
		switch v := actual.(type) {
		case int:
			var want int
			_ = json.Unmarshal(p.Value, &want)
			if p.Op == "eq" && v != want || p.Op == "neq" && v == want || p.Op == "gte" && v < want || p.Op == "lte" && v > want {
				return false
			}
		case string:
			var want string
			_ = json.Unmarshal(p.Value, &want)
			if p.Op == "eq" && v != want || p.Op == "neq" && v == want {
				return false
			}
		case bool:
			var want bool
			_ = json.Unmarshal(p.Value, &want)
			if v != want {
				return false
			}
		}
	}
	return true
}

type Gap struct {
	Reason   string    `json:"reason"`
	SourceID *string   `json:"source_session_id"`
	Count    *int      `json:"count"`
	From     time.Time `json:"from"`
	Until    time.Time `json:"until"`
}
type Handling struct {
	Transient  bool   `json:"transient"`
	UserData   bool   `json:"may_contain_user_data"`
	RowAge     int    `json:"managed_row_max_age_seconds"`
	Raw        bool   `json:"raw_available_live"`
	Recallable bool   `json:"external_copies_recallable"`
	Save       string `json:"save_semantics"`
}

func Notices() Handling {
	return Handling{Transient: true, UserData: true, RowAge: 30, Save: "freshCurrentWindow"}
}

type Limits struct {
	Duration int   `json:"duration_seconds"`
	Output   int64 `json:"max_output_bytes"`
	Rate     int64 `json:"bytes_per_second"`
	Rows     int   `json:"max_rows_per_batch"`
	Buffer   int   `json:"max_buffer_bytes"`
	RowAge   int   `json:"row_max_age_seconds"`
	Replay   int   `json:"replay_seconds"`
}

func DefaultLimits() Limits { return Limits{600, 16 << 20, 64 << 10, 100, MaxBufferBytes, 30, 5} }
func (l Limits) Valid() bool {
	return l.Duration > 0 && l.Duration <= 3600 && l.Output > 0 && l.Output <= 64<<20 && l.Rate > 0 && l.Rate <= 256<<10 && l.Rows > 0 && l.Rows <= MaxRows && l.Buffer > 0 && l.Buffer <= MaxBufferBytes && l.RowAge > 0 && l.RowAge <= 30 && l.Replay >= 0 && l.Replay <= 5
}

type Watch struct {
	ID         string    `json:"watch_id"`
	Revision   int64     `json:"revision"`
	State      string    `json:"state"`
	SourceIDs  []string  `json:"source_session_ids"`
	Projection string    `json:"projection"`
	AcceptedAt time.Time `json:"accepted_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IdleUntil  time.Time `json:"idle_expires_at"`
	Limits     Limits    `json:"limits"`
	Cursor     *string   `json:"cursor"`
	Handling   Handling  `json:"handling"`
}
type SourceStatus struct {
	ID           string     `json:"source_session_id"`
	State        string     `json:"state"`
	Generation   int64      `json:"filter_generation"`
	LastObserved *time.Time `json:"last_observed_at"`
	Coverage     string     `json:"coverage"`
}
type Batch struct {
	// DisclosureUntil is the original private authority bound, never public data.
	DisclosureUntil time.Time      `json:"-"`
	Cursor          string         `json:"-"`
	WatchID         string         `json:"watch_id"`
	Revision        int64          `json:"revision"`
	ID              string         `json:"batch_id"`
	State           string         `json:"state"`
	Rows            []Row          `json:"rows"`
	Sources         []SourceStatus `json:"sources"`
	Gaps            []Gap          `json:"gaps"`
	From            time.Time      `json:"interval_from"`
	Until           time.Time      `json:"interval_until"`
	ReceivedAt      time.Time      `json:"received_at"`
	Spent           int64          `json:"output_bytes_spent"`
	RetryAfter      int            `json:"retry_after_ms"`
	Handling        Handling       `json:"handling"`
}

// CloneFilter gives the accepted viewer immutable ownership of authored values.
func CloneFilter(f Filter) Filter {
	out := Filter{All: make([]Predicate, len(f.All))}
	for n, p := range f.All {
		p.Value = append(json.RawMessage(nil), p.Value...)
		out.All[n] = p
	}
	return out
}
func CloneBatch(b Batch) Batch {
	b.Rows = append([]Row{}, b.Rows...)
	for n, r := range b.Rows {
		b.Rows[n] = r.Clone()
	}
	b.Sources = append([]SourceStatus{}, b.Sources...)
	for n, r := range b.Sources {
		if r.LastObserved != nil {
			t := *r.LastObserved
			b.Sources[n].LastObserved = &t
		}
	}
	b.Gaps = append([]Gap{}, b.Gaps...)
	for n, g := range b.Gaps {
		if g.SourceID != nil {
			id := *g.SourceID
			b.Gaps[n].SourceID = &id
		}
		if g.Count != nil {
			count := *g.Count
			b.Gaps[n].Count = &count
		}
	}
	return b
}

// Tighten retains every original accepted ceiling; it never replenishes spend.
func (l Limits) Tighten(other Limits) Limits {
	return Limits{min(l.Duration, other.Duration), min(l.Output, other.Output), min(l.Rate, other.Rate), min(l.Rows, other.Rows), min(l.Buffer, other.Buffer), min(l.RowAge, other.RowAge), min(l.Replay, other.Replay)}
}
