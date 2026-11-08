package live

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

// Source is independently supplied by the ongoing source authority adapter.
// It is never decoded from a public caller. A valid value is not authorization.
type Source struct {
	// Manual preserves the actual finite observation identity; no policy or
	// acceptance is invented for a manual source. The alternatives are exclusive.
	Manual                              *collector.ManualLiveSource
	RootID                              string
	ViewLimits                          Limits
	Binding                             collector.SourceBinding
	Target                              authorization.Target
	OwnerKind, OwnerID, State, SaveVia  string
	Projections                         []string
	Blockers                            []string
	LeaseUntil, HardUntil, PrivacyUntil time.Time
	Generation                          int64
}

func (s Source) ReferenceValid() bool {
	if !slices.Contains([]string{"Warming", "Ready", "Degraded", "Stopped", "Unavailable"}, s.State) || !slices.Contains([]string{"recordingSave", "captureOutcome", "unavailable"}, s.SaveVia) || !s.identityValid() || !s.Target.Valid() || s.Target.PodUID != s.Pod() || s.LeaseUntil.IsZero() || s.HardUntil.IsZero() || s.LeaseUntil.After(s.HardUntil) || s.PrivacyUntil.IsZero() || len(s.Projections) > 3 || s.Generation < 0 || s.Generation > 1000000000 {
		return false
	}
	for n, p := range s.Projections {
		if !Projection(p) {
			return false
		}
		for _, prior := range s.Projections[:n] {
			if prior == p {
				return false
			}
		}
	}
	if len(s.Blockers) > 16 {
		return false
	}
	for _, b := range s.Blockers {
		if !identity.Text(b, 64) || b == "" {
			return false
		}
	}
	return true
}
func (s Source) Valid(now time.Time) bool {
	return s.ReferenceValid() && now.Before(s.LeaseUntil) && now.Before(s.PrivacyUntil)
}
func (s Source) identityValid() bool {
	if s.Manual == nil {
		return s.OwnerKind == "policy" && s.Binding.Valid() && s.OwnerID == s.Binding.PolicyUID
	}
	m := s.Manual
	return s.OwnerKind == "manualSession" && s.Binding == (collector.SourceBinding{}) && authorization.UUID(s.RootID) && m.RootID == s.RootID && m.Valid() && s.OwnerID == m.CaptureID && s.HardUntil.Equal(m.HardUntil)
}
func (s Source) ID() string {
	if s.Manual != nil {
		return s.Manual.CaptureID
	}
	return s.Binding.SourceID
}
func (s Source) Pod() string {
	if s.Manual != nil {
		return s.Manual.PodUID
	}
	return s.Binding.PodUID
}
func (s Source) Action() string {
	if s.Manual != nil {
		return s.Manual.ActionID
	}
	return s.Binding.ActionID
}
func (s Source) Root() string {
	if s.Manual != nil {
		return s.RootID
	}
	return s.Binding.RootID
}
func (s Source) Fence() string {
	if s.Manual != nil {
		return s.Manual.WorkID
	}
	return s.Binding.Fence
}
func (s Source) Boot() string {
	if s.Manual != nil {
		return s.Manual.BootID
	}
	return s.Binding.BootID
}
func (s Source) Same(other Source) bool {
	if (s.Manual == nil) != (other.Manual == nil) {
		return false
	}
	if s.Manual != nil && (*s.Manual != *other.Manual || s.RootID != other.RootID) {
		return false
	}
	return s.Binding == other.Binding && s.Target == other.Target && s.OwnerKind == other.OwnerKind && s.OwnerID == other.OwnerID && s.HardUntil.Equal(other.HardUntil) && s.PrivacyUntil.Equal(other.PrivacyUntil)
}
func (s Source) Clone() Source {
	s.Projections = append([]string(nil), s.Projections...)
	s.Blockers = append([]string(nil), s.Blockers...)
	if s.Manual != nil {
		m := *s.Manual
		s.Manual = &m
	}
	return s
}

type SourceRow struct {
	Handle        string    `json:"source_handle"`
	HandleExpires time.Time `json:"handle_expires_at"`
	ID            string    `json:"source_session_id"`
	WorkloadUID   string    `json:"workload_uid"`
	PodUID        string    `json:"pod_uid"`
	ActionID      string    `json:"action_id"`
	OwnerKind     string    `json:"owner_kind"`
	OwnerID       string    `json:"owner_id"`
	State         string    `json:"state"`
	Projections   []string  `json:"projections"`
	Eligible      bool      `json:"eligible"`
	Blockers      []string  `json:"blocker_codes"`
	SaveVia       string    `json:"save_via"`
	LeaseUntil    time.Time `json:"lease_until"`
}
type SourcePage struct {
	Sources []SourceRow `json:"sources"`
}
type Open struct {
	Handles    []string `json:"source_handles"`
	Projection string   `json:"projection"`
	Filter     Filter   `json:"display_filter,omitzero"`
	Duration   int      `json:"duration_seconds,omitempty"`
	Output     int64    `json:"max_output_bytes,omitempty"`
	Key        string   `json:"idempotency_key"`
}

func (r Open) Valid() bool {
	if !identity.Text(r.Key, 128) || r.Key == "" || !r.Filter.Valid(r.Projection) || len(r.Handles) < 1 || len(r.Handles) > MaxSources || r.Duration < 0 || r.Duration > 3600 || r.Output < 0 || r.Output > 64<<20 {
		return false
	}
	for n, h := range r.Handles {
		if !identity.Text(h, 128) || h == "" {
			return false
		}
		for _, prior := range r.Handles[:n] {
			if prior == h {
				return false
			}
		}
	}
	return true
}

type Read struct {
	ID     string `json:"watch_id"`
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit,omitempty"`
	WaitMS int    `json:"wait_ms,omitempty"`
}

func (r Read) Valid() bool {
	return authorization.UUID(r.ID) && identity.Text(r.Cursor, 4096) && r.Cursor != "" && r.Limit >= 0 && r.Limit <= 100 && r.WaitMS >= 0 && r.WaitMS <= 5000
}

type Update struct {
	ID       string  `json:"watch_id"`
	Revision int64   `json:"expected_revision"`
	Key      string  `json:"idempotency_key"`
	Mode     string  `json:"mode,omitempty"`
	Filter   *Filter `json:"display_filter,omitempty"`
}

func (r Update) Valid() bool {
	return authorization.UUID(r.ID) && r.Revision > 0 && r.Revision <= 1000000000 && identity.Text(r.Key, 128) && r.Key != "" && (r.Mode == "" || r.Mode == "Active" || r.Mode == "Paused")
}
