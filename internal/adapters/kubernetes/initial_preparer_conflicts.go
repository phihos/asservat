package kubernetes

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A retained negative result belongs to one actual local UPDATE invocation.
// Public GET observations cannot create it. There are exactly two purposes.
type initialHandoverConflict struct {
	Purpose, ID, UID, ResourceVersion string
	StartedAt, Until, CompletedAt     time.Time
}

func (s *InitialPreparer) conflictBinding(w contracts.InitialPreparationRoot, purpose string) (initialHandoverConflict, error) {
	var out initialHandoverConflict
	if !s.HandoverEnabled() || w.Activation == nil || w.Activation.Handover == nil {
		return out, cfg.ErrChanged
	}
	h := w.Activation.Handover
	out.Purpose = purpose
	switch purpose {
	case "staging":
		if h.Staging == nil {
			return out, cfg.ErrChanged
		}
		out.ID = h.Staging.ID
		out.UID = s.staging.PolicyUID
		out.ResourceVersion = h.Staging.PolicyResourceVersion
		out.StartedAt = h.Staging.StartedAt
		out.Until = h.Staging.Until
	case "launch":
		if h.Launch == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil {
			return out, cfg.ErrChanged
		}
		out.ID = h.Launch.ID
		out.UID = w.Activation.Pod.Receipt.UID
		out.ResourceVersion = h.Launch.PodResourceVersion
		out.StartedAt = h.Launch.StartedAt
		out.Until = h.Launch.Until
	default:
		return out, cfg.ErrInvalid
	}
	return out, nil
}

func initialHandoverConflictStatus(raw []byte, status int, group, resource, name string) bool {
	if status != http.StatusConflict || permissionJSON(raw, 4096, 128) != nil {
		return false
	}
	var v meta.Status
	if strictGuardJSON(raw, &v) != nil || v.APIVersion != "v1" || v.Kind != "Status" || v.Status != meta.StatusFailure || v.Code != http.StatusConflict || v.Reason != meta.StatusReasonConflict || v.Details == nil || !identity.Text(v.Message, 2048) {
		return false
	}
	d := v.Details
	return v.ListMeta == (meta.ListMeta{}) && d.Group == group && d.Kind == resource && d.Name == name && d.UID == "" && len(d.Causes) == 0 && d.RetryAfterSeconds == 0
}

func (s *InitialPreparer) retainHandoverConflict(ctx context.Context, w contracts.InitialPreparationRoot, purpose string, raw []byte, status int) bool {
	binding, e := s.conflictBinding(w, purpose)
	if e != nil || initialHandoverDeadline(ctx, s.protection.observer.now, binding.Until) != nil {
		return false
	}
	group, resource, name := "", "pods", s.plan.Workload.Name
	if purpose == "staging" {
		group = "admissionregistration.k8s.io"
		resource = "validatingadmissionpolicies"
		name = s.plan.Workload.StagingGuard
	}
	if !initialHandoverConflictStatus(raw, status, group, resource, name) {
		return false
	}
	binding.CompletedAt = s.protection.observer.now().UTC().Truncate(time.Microsecond)
	if binding.CompletedAt.Before(binding.StartedAt) || !binding.CompletedAt.Before(binding.Until) {
		return false
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if s.handoverConflicts == nil {
		s.handoverConflicts = map[string]initialHandoverConflict{}
	}
	if prior, ok := s.handoverConflicts[purpose]; ok {
		return prior == binding
	}
	if len(s.handoverConflicts) >= 2 {
		return false
	}
	s.handoverConflicts[purpose] = binding
	return true
}

// persistHandoverConflict only completes persistence of this owner's retained
// exact negative response, still within the parent's original effect interval.
func (s *InitialPreparer) persistHandoverConflict(ctx context.Context, cm *core.ConfigMap, w contracts.InitialPreparationRoot, purpose string, until time.Time) (*core.ConfigMap, contracts.InitialPreparationRoot, error) {
	binding, e := s.conflictBinding(w, purpose)
	if e != nil {
		return nil, w, e
	}
	h := w.Activation.Handover
	if purpose == "staging" && h.Staging.FirstConflict != nil || purpose == "launch" && h.Launch.FirstConflict != nil {
		return cm, w, nil
	}
	s.requestMu.Lock()
	retained, ok := s.handoverConflicts[purpose]
	s.requestMu.Unlock()
	if !ok {
		return cm, w, nil
	}
	binding.CompletedAt = retained.CompletedAt
	if binding != retained {
		return nil, w, cfg.ErrChanged
	}
	until = identity.Earlier(until, binding.Until)
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return nil, w, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	completion := &contracts.InitialPreparationConflictCompletion{CompletedAt: retained.CompletedAt}
	if purpose == "staging" {
		h.Staging.FirstConflict = completion
	} else {
		h.Launch.FirstConflict = completion
	}
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return nil, w, e
	}
	cm, w, e = s.read(ctx)
	if e != nil {
		return nil, w, e
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return nil, w, e
	}
	return cm, w, nil
}

// The raw result is independently parsed before retaining a negative completion.
// client-go may synthesize a StatusError from arbitrary HTTP responses; that
// synthesized error is deliberately not accepted as original no-effect proof.
func (s *InitialPreparer) conditionalHandoverPut(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	var status int
	result := s.creator.api.Put().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).Do(ctx)
	result.StatusCode(&status)
	raw, e := result.Raw()
	if e == nil && status != http.StatusOK {
		return raw, status, cfg.ErrUnavailable
	}
	return raw, status, e
}
