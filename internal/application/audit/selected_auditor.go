package audit

import (
	"context"
	"encoding/json"
	"sync"

	value "asservat.local/asservat/internal/domain/audit"
)

// SelectedOperationAuditor reads the lane's current accepted capacity profile
// before each new Begin (ADR-190) and finishes each operation with the policy
// its intent was bound to, so a renewal never rebinds work in flight. It keeps
// one healthy auditor per policy, built on first use; at most four.
type SelectedOperationAuditor struct {
	lane     string
	profiles CapacityAuditProfiles
	build    func(context.Context, value.OperationLifecyclePolicy) (*HealthyOperationAuditor, error)
	mu       sync.Mutex
	built    []selectedAuditor
	// inflight remembers each begun intent's policy: callers finish with the
	// original intent, whose lifecycle binding stays inside the auditor.
	inflight map[string]value.OperationLifecyclePolicy
	order    []string
}

type selectedAuditor struct {
	key     string
	auditor *HealthyOperationAuditor
}

func NewSelectedOperationAuditor(lane string, profiles CapacityAuditProfiles, build func(context.Context, value.OperationLifecyclePolicy) (*HealthyOperationAuditor, error)) (*SelectedOperationAuditor, error) {
	if lane != "normal" && lane != "resolution" || profiles == nil || build == nil {
		return nil, ErrUnavailable
	}
	return &SelectedOperationAuditor{lane: lane, profiles: profiles, build: build}, nil
}

func (s *SelectedOperationAuditor) Configured() bool {
	return s != nil && s.profiles != nil && s.build != nil
}

func (s *SelectedOperationAuditor) Begin(ctx context.Context, in value.OperationIntent) error {
	if s == nil || ctx == nil {
		return ErrUnavailable
	}
	accepted, err := s.profiles.ReadCapacityAuditProfiles(ctx)
	if err != nil {
		return ErrUnavailable
	}
	profile := accepted.Normal
	if s.lane == "resolution" {
		profile = accepted.Resolution
	}
	a, err := s.auditor(ctx, profile.Policy)
	if err != nil {
		return err
	}
	s.remember(in.ID, profile.Policy)
	return a.Begin(ctx, in)
}

// remember keeps the begun intent's policy until its Finish; at most 1024
// entries, oldest first. A Finish without an entry fails closed; overdue
// recovery then owns the original intent.
func (s *SelectedOperationAuditor) remember(id string, p value.OperationLifecyclePolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]value.OperationLifecyclePolicy{}
	}
	if _, ok := s.inflight[id]; !ok {
		s.order = append(s.order, id)
	}
	s.inflight[id] = p
	for len(s.order) > 1024 {
		delete(s.inflight, s.order[0])
		s.order = s.order[1:]
	}
}

func (s *SelectedOperationAuditor) Finish(ctx context.Context, out value.OperationOutcome) error {
	if s == nil || ctx == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	p, ok := s.inflight[out.Intent.ID]
	s.mu.Unlock()
	if l := out.Intent.Lifecycle; l != nil {
		if ok && !sameOperationPolicy(l.Policy, p) {
			return ErrUnavailable
		}
		p, ok = l.Policy, true
	}
	if !ok {
		return ErrUnavailable
	}
	a, err := s.auditor(ctx, p)
	if err != nil {
		return err
	}
	return a.Finish(ctx, out)
}

func sameOperationPolicy(a, b value.OperationLifecyclePolicy) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}

func (s *SelectedOperationAuditor) auditor(ctx context.Context, p value.OperationLifecyclePolicy) (*HealthyOperationAuditor, error) {
	if p.Lane != s.lane {
		return nil, ErrUnavailable
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, ErrUnavailable
	}
	key := string(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.built {
		if b.key == key {
			return b.auditor, nil
		}
	}
	a, err := s.build(ctx, p)
	if err != nil || !a.Configured() {
		return nil, ErrUnavailable
	}
	// ponytail: four recent policies; an older in-flight Finish rebuilds its own.
	s.built = append(s.built, selectedAuditor{key, a})
	if len(s.built) > 4 {
		s.built = s.built[1:]
	}
	return a, nil
}
