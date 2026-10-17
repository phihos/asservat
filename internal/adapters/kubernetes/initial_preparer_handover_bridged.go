package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// bridgedFinal returns the guard bridge's phase guard for a fresh reader
// after the bridge (ADR-187), or nil before it. The guard is recomputed from
// the original installer input and three journal receipts with the bridge's
// own builders; journal bytes only select which candidate the existing proof
// then checks for exact equality. allowProbe also admits the intermediate
// phase, for a resumed producer.
func (s *InitialPreparer) bridgedFinal(ctx context.Context, allowProbe bool) (*configMapProtection, int, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, 0, cfg.ErrInvalid
	}
	if !s.HandoverEnabled() {
		return nil, 0, nil
	}
	// Selection only: the caller's currentHandoverWithFinal runs the complete
	// administrator, protection and exact-guard proof on the chosen candidate.
	_, root, err := s.read(ctx)
	if err != nil || root.Activation == nil || root.Activation.Handover == nil {
		// Not handed over yet: the original guard applies unchanged.
		return nil, 0, nil
	}
	c, err := s.inputConfiguration(root)
	if err != nil {
		return nil, 0, cfg.ErrChanged
	}
	base, err := s.finalHandoverProtection(c)
	if err != nil {
		return nil, 0, err
	}
	raw, err := base.observer.raw(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+base.plan.Name, nil)
	if err != nil {
		return nil, 0, cfg.ErrUnavailable
	}
	var policy admission.ValidatingAdmissionPolicy
	if json.Unmarshal(raw, &policy) != nil || policy.UID != types.UID(base.pin.PolicyUID) {
		return nil, 0, cfg.ErrChanged
	}
	phase := policy.Generation - base.pin.PolicyGeneration
	switch {
	case phase == 0:
		return nil, 0, nil
	case phase == 2, phase == 1 && allowProbe:
	default:
		return nil, 0, cfg.ErrChanged
	}
	state, err := s.readResourceJournal(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	o := state.Objects
	ref := func(i int, name string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: o[i].Receipt.UID}
	}
	n := runtimeResourceNames(c.InstallationID)
	a, err := s.runtimeBridgeAdministration(c, state.OwnerLayout, ref(10, n.Owner), ref(0, n.Owner), ref(1, n.Worker))
	if err != nil {
		return nil, 0, err
	}
	_, guards, err := initialRuntimeBridgeGuards(s, c, a)
	if err != nil {
		return nil, 0, err
	}
	return guards[phase], int(phase), nil
}

// readResourceJournal reads the original resource journal with a plain GET.
// Its receipts only select a candidate guard; it grants nothing by itself.
func (s *InitialPreparer) readResourceJournal(ctx context.Context, c contracts.InitialInstaller) (contracts.InitialRuntimeResourceState, error) {
	var zero contracts.InitialRuntimeResourceState
	name := "asservat-runtime-resources-" + strings.ReplaceAll(c.InstallationID, "-", "")
	raw, err := s.creator.raw(ctx, "/api/v1/namespaces/"+c.Namespace.Name+"/secrets/"+name, nil)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var secret core.Secret
	if json.Unmarshal(raw, &secret) != nil || secret.Name != name || secret.Namespace != c.Namespace.Name || len(secret.Data) != 1 {
		return zero, cfg.ErrChanged
	}
	state, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(secret.Data["state.json"]))
	if err != nil || len(state.Objects) != len(initialRuntimeResourceItems) || state.CreatedAt.After(time.Now()) {
		return zero, cfg.ErrChanged
	}
	for i, object := range state.Objects {
		if object.Item != initialRuntimeResourceItems[i] || object.Receipt == nil || !authorization.UUID(object.Receipt.UID) {
			return zero, cfg.ErrChanged
		}
	}
	switch state.OwnerLayout {
	case "", contracts.OwnerInstalledLayout, contracts.OwnerProviderInstalledLayout:
	default:
		return zero, cfg.ErrChanged
	}
	return state, nil
}

// passiveHandover is the read-only handover check after the bridge: the
// original guard before it, the retained phase-two guard after it. Effect
// paths keep currentHandover and the original guard (ADR-187).
func (s *InitialPreparer) passiveHandover(ctx context.Context) (*core.ConfigMap, contracts.InitialPreparationRoot, contracts.InitialInstaller, time.Time, error) {
	alternate, _, err := s.bridgedFinal(ctx, false)
	if err != nil {
		return nil, contracts.InitialPreparationRoot{}, contracts.InitialInstaller{}, time.Time{}, err
	}
	return s.currentHandoverWithFinal(ctx, alternate)
}
