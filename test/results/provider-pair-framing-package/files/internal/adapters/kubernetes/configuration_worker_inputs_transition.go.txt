package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// Exactly one new claim or one positive receipt. No old permit, sibling or
// original object changes, and a positive receipt can never be replaced.
func configurationWorkerInputTransition(old, next contracts.InitialRuntimeResourceState) bool {
	if next.WorkerInputs == nil {
		return false
	}
	a, b := old, next
	a.WorkerInputs = nil
	b.WorkerInputs = nil
	if !equalJSON(a, b) {
		return false
	}
	p, q := old.WorkerInputs, next.WorkerInputs
	if p == nil {
		return q.Receipt == nil
	}
	if p.Receipt != nil || q.Receipt == nil {
		return false
	}
	c, d := *p, *q
	c.Receipt = nil
	d.Receipt = nil
	return equalJSON(c, d)
}

func (s *ConfigurationWorkerInputs) write(ctx context.Context, old contracts.InitialRuntimeResourceSnapshot, obj *core.Secret, next contracts.InitialRuntimeResourceState, until time.Time) (contracts.InitialRuntimeResourceSnapshot, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	if obj == nil || obj.UID == "" || string(obj.UID) != old.UID || obj.ResourceVersion != old.ResourceVersion ||
		!configurationWorkerInputTransition(old.State, next) || !s.resources.valid(next) {
		return zero, cfg.ErrChanged
	}
	if !s.resources.now().Before(old.State.Until) {
		return zero, cfg.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, until)
	defer end()
	// A current retained native proof brackets each CAS independently. This
	// preserves all original source/SQL/provider bounds in the incoming context.
	current, _, err := s.readResources(call)
	if err != nil {
		return zero, err
	}
	if current.UID != old.UID || current.ResourceVersion != old.ResourceVersion || !equalJSON(current.State, old.State) {
		return zero, cfg.ErrChanged
	}
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > contracts.InitialRuntimeResourcesMaxBytes {
		return zero, cfg.ErrInvalid
	}
	body := obj.DeepCopy()
	body.Data = map[string][]byte{"state.json": raw}
	reply, err := s.roles.client.api.Put().AbsPath(s.resources.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(call)
	defer clear(reply)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	got, _, err := s.resources.decode(call, reply)
	if err != nil {
		return zero, err
	}
	if got.UID != old.UID || got.ResourceVersion == old.ResourceVersion || !equalJSON(got.State, next) {
		return zero, cfg.ErrChanged
	}
	after, _, err := s.readResources(call)
	if err != nil {
		return zero, err
	}
	if after.UID != got.UID || after.ResourceVersion != got.ResourceVersion || !equalJSON(after.State, next) {
		return zero, cfg.ErrChanged
	}
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	return after, nil
}
