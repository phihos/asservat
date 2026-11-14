package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// Runs only within the original bridge SQL callback. It does not invoke the
// old resource current() path or a post-launch producer to establish its own
// prerequisites. All nineteen receipts and immutable parent facts are checked
// under the concrete retained guard before accepting this observation.
func (s *ConfigurationWorkerInputs) readResources(ctx context.Context) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	before, _, _, phase, err := s.bridge.readCurrent(ctx)
	if err != nil {
		return zero, nil, err
	}
	if phase != 2 || before.State.Probe == nil || before.State.Probe.Receipt == nil || before.State.Retained == nil || before.State.Retained.Receipt == nil {
		return zero, nil, cfg.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, before.ValidUntil)
	defer end()
	v, obj, err := s.resources.read(call)
	if err != nil {
		return zero, nil, err
	}
	a, b := v.State, s.original.State
	if v.UID != s.original.UID || a.SetupID != b.SetupID || a.BindingDigest != b.BindingDigest || !a.CreatedAt.Equal(b.CreatedAt) || !a.Until.Equal(b.Until) ||
		a.WorkerLayout != b.WorkerLayout || a.OwnerLayout != b.OwnerLayout || !equalJSON(a.WorkerProvider, b.WorkerProvider) || !equalJSON(a.OwnerProvider, b.OwnerProvider) || !equalJSON(a.Objects, b.Objects) {
		return zero, nil, cfg.ErrChanged
	}
	inventory, err := s.resources.inventory(v.State)
	if err != nil || !equalJSON(inventory.BridgeAdministration, s.bridge.administration) {
		return zero, nil, cfg.ErrChanged
	}
	after, _, _, phase, err := s.bridge.readCurrent(call)
	if err != nil {
		return zero, nil, err
	}
	v.ValidUntil = identity.Earlier(v.ValidUntil, identity.Earlier(before.ValidUntil, after.ValidUntil))
	if phase != 2 || before.UID != after.UID || !equalJSON(before.State, after.State) {
		return zero, nil, cfg.ErrChanged
	}
	if initialHandoverDeadline(call, s.resources.now, v.ValidUntil) != nil {
		return zero, nil, cfg.ErrUnavailable
	}
	return v, obj, nil
}
