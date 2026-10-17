package kubernetes

import (
	"bytes"
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

const initialPreparationRetiredAnnotation = "asservat.io/initial-preparation-retired"

var initialPreparationCleanupSteps = [...]string{"sql", "wrap", "unwrap", "probe", "target-secrets", "setup-rbac", "private-state", "pod"}

// These are purpose-specific rights reductions, never alternative issuance or
// historical lookup ports. The concrete SQL owner revokes existing-session
// effects; the provider verifies the exact original child/accessor rejection.
type InitialPreparationRetirer interface {
	RetireInitialSQL(context.Context, contracts.InitialSQLCredentialState) error
	RetireInitialProvider(context.Context, string, contracts.InitialProviderParent, contracts.InitialProviderIssue, contracts.InitialProviderResponse) error
}

func (s *InitialPreparer) validHandoverCleanup(w contracts.InitialPreparationRoot) bool {
	if w.Activation == nil || w.Activation.Handover == nil {
		return false
	}
	h := w.Activation.Handover
	c := h.Cleanup
	if c == nil {
		return true
	}
	if h.Staging == nil || h.Staging.Receipt == nil || h.Launch == nil || !h.Launch.Observed || !authorization.UUID(c.OperationID) || !authorization.UUID(c.ActivatedClaimID) || c.OperationID == h.OperationID || c.OperationID == h.Launch.ID || c.OperationID == h.Staging.ID || !initialHandoverTime(c.StartedAt) || c.StartedAt.Before(h.Launch.StartedAt) || !identity.Text(c.PodResourceVersion, 128) || c.SQLState.Name != s.plan.Workload.Credentials+"-sql" || !authorization.UUID(c.SQLState.UID) || c.ProbeAnchor.Name != s.probeAnchorName() || !authorization.UUID(c.ProbeAnchor.UID) || c.Steps == nil || len(c.Steps) > len(initialPreparationCleanupSteps) {
		return false
	}
	for _, r := range w.Creates {
		if r.OperationID == c.OperationID {
			return false
		}
	}
	if w.Activation.Pod != nil && w.Activation.Pod.OperationID == c.OperationID {
		return false
	}
	if w.Activation.Inputs != nil {
		for _, r := range w.Activation.Inputs.Creates {
			if r.OperationID == c.OperationID {
				return false
			}
		}
	}
	previous := c.StartedAt
	for i, r := range c.Steps {
		if r.Step != initialPreparationCleanupSteps[i] || !initialHandoverTime(r.CompletedAt) || r.CompletedAt.Before(previous) {
			return false
		}
		previous = r.CompletedAt
	}
	return true
}
func (s *InitialPreparer) HandoverCleanupComplete(w contracts.InitialPreparationRoot) bool {
	return s.HandoverEnabled() && w.Activation != nil && w.Activation.Handover != nil && w.Activation.Handover.Cleanup != nil && s.validHandoverCleanup(w) && len(w.Activation.Handover.Cleanup.Steps) == len(initialPreparationCleanupSteps)
}

// BeginHandoverCleanup binds the independently verified historical SQL result
// to a positively joined original process and all original Secret CREATEs.
// It cannot retire an unknown/failed writer or activate/recover a database.
func (s *InitialPreparer) BeginHandoverCleanup(ctx context.Context, observed app.InitialInstallationObservation) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	if observed.Disposition != app.InitialInstallationActivated || observed.Record == nil || !observed.Record.Valid() || observed.AuditReceipt == nil || !observed.AuditReceipt.ValidInitialInstallation(observed.Record.Scope.InstallationID, observed.Record.Claim.ID) || observed.ActivatedAt.IsZero() {
		return zero, cfg.ErrChanged
	}
	if e := initialHandoverDeadline(ctx, s.protection.observer.now, observed.ValidUntil); e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, observed.ValidUntil)
	defer end()
	cm, w, c, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, e
	}
	until = identity.Earlier(until, observed.ValidUntil)
	digest, e := initialPreparationDigest(w.Activation.Credentials.StartupDigest)
	if e != nil || initialPreparationWitnessScope(c) != observed.Record.Scope || observed.Record.Claim.PlanDigest != digest {
		return zero, cfg.ErrChanged
	}
	h := w.Activation.Handover
	if h == nil || h.Launch == nil || !h.Launch.Observed {
		return zero, cfg.ErrChanged
	}
	if h.Cleanup != nil {
		if h.Cleanup.ActivatedClaimID != observed.Record.Claim.ID {
			return zero, cfg.ErrChanged
		}
		return w, nil
	}
	raw, e := s.creator.raw(ctx, s.handoverPodPath(), nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	pod, e := s.handoverPod(raw, w, false)
	if e != nil || !s.successfulHandoverPod(pod, w) {
		return zero, cfg.ErrChanged
	}
	_, private, e := s.readPrivate(ctx)
	if e != nil || private.RootUID != w.RootUID || private.Probe == nil || !private.Probe.CreateClosed || private.Probe.Anchor == nil || private.SQL == nil || !private.SQL.CreateClosed || private.SQL.Secret == nil || private.Providers == nil || private.Providers.Projection == nil || !private.Providers.Projection.CreateClosed || private.Providers.Projection.Secret == nil || *private.Providers.Projection.Secret != h.Credentials {
		return zero, ErrInitialPreparationRequestsUnresolved
	}
	for _, r := range w.Activation.Pod.Requests {
		if r.Completion == nil {
			return zero, ErrInitialPreparationRequestsUnresolved
		}
	}
	id, e := prepUUID()
	if e != nil {
		return zero, e
	}
	h.Cleanup = &contracts.InitialPreparationCleanup{OperationID: id, ActivatedClaimID: observed.Record.Claim.ID, StartedAt: s.protection.observer.now().UTC().Truncate(time.Microsecond), PodResourceVersion: pod.ResourceVersion, SQLState: *private.SQL.Secret, ProbeAnchor: contracts.WorkerObjectReference{Name: s.probeAnchorName(), UID: private.Probe.Anchor.UID}, Steps: []contracts.InitialPreparationCleanupReceipt{}}
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}
func (s *InitialPreparer) handoverPodPath() string {
	return "/api/v1/namespaces/" + s.plan.Workload.Namespace + "/pods/" + s.plan.Workload.Name
}
func (s *InitialPreparer) successfulHandoverPod(pod *core.Pod, w contracts.InitialPreparationRoot) bool {
	if pod == nil || pod.Status.Phase != core.PodSucceeded || len(pod.Status.ContainerStatuses) != 1 || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
		return false
	}
	c := pod.Status.ContainerStatuses[0]
	v := c.State.Terminated
	return c.Name == pod.Spec.Containers[0].Name && c.RestartCount == 0 && v != nil && v.ExitCode == 0 && initialPreparationTerminalTimes(v.StartedAt.Time, v.FinishedAt.Time, w.Activation.Handover.Launch.StartedAt, s.protection.observer.now())
}

// RetireHandover advances at most one fixed step per invocation. Lost replies
// repeat only an idempotent rights reduction or exact absence observation.
// Each call gets current operator checks; no original credential date changes.
func (s *InitialPreparer) RetireHandover(ctx context.Context, retirer InitialPreparationRetirer) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	cm, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, e
	}
	h := w.Activation.Handover
	if h == nil || h.Cleanup == nil {
		return zero, cfg.ErrChanged
	}
	if s.HandoverCleanupComplete(w) {
		return w, nil
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	step := len(h.Cleanup.Steps)
	switch step {
	case 0:
		if retirer == nil {
			return zero, cfg.ErrUnavailable
		}
		sql, e := s.handoverSQLState(ctx, w)
		if e != nil {
			return zero, e
		}
		if e = retirer.RetireInitialSQL(ctx, sql); e != nil {
			return zero, e
		}
	case 1, 2:
		if retirer == nil {
			return zero, cfg.ErrUnavailable
		}
		_, private, e := s.readPrivate(ctx)
		if e != nil || private.RootUID != w.RootUID || private.Providers == nil {
			return zero, cfg.ErrChanged
		}
		p := private.Providers
		i := p.Wrap
		purpose := "wrap"
		if step == 2 {
			i = p.Unwrap
			purpose = "unwrap"
		}
		if i == nil || i.Response == nil {
			return zero, cfg.ErrChanged
		}
		if e = retirer.RetireInitialProvider(ctx, purpose, p.Parent, *i, *i.Response); e != nil {
			return zero, e
		}
	case 3:
		e = s.retireHandoverProbe(ctx, w)
	case 4:
		e = s.retireHandoverTargets(ctx, w)
	case 5:
		e = s.retireHandoverRBAC(ctx, w)
	case 6:
		e = s.retireHandoverPrivate(ctx, w)
	case 7:
		e = s.retireHandoverPod(ctx, w)
	default:
		return zero, cfg.ErrInvalid
	}
	if e != nil {
		return zero, e
	}
	h.Cleanup.Steps = append(h.Cleanup.Steps, contracts.InitialPreparationCleanupReceipt{Step: initialPreparationCleanupSteps[step], CompletedAt: s.protection.observer.now().UTC().Truncate(time.Microsecond)})
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}
func (s *InitialPreparer) handoverSQLState(ctx context.Context, w contracts.InitialPreparationRoot) (contracts.InitialSQLCredentialState, error) {
	var zero contracts.InitialSQLCredentialState
	ref := w.Activation.Handover.Cleanup.SQLState
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/secrets/"+ref.Name, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil || !ownerMetadata(secret.ObjectMeta, s.plan.Workload.Namespace, ref.Name, ref.UID) || secret.Type != core.SecretTypeOpaque || secret.Immutable == nil || !*secret.Immutable || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.Data) != 1 || len(secret.StringData) != 0 {
		return zero, cfg.ErrChanged
	}
	defer func() {
		for _, b := range secret.Data {
			clear(b)
		}
	}()
	sql, e := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(secret.Data["state.json"]))
	b := w.Activation.Credentials
	if e != nil || sql.Format != contracts.InitialSQLCredentialsFormat || sql.InstallationID != w.InstallationID || sql.PlanDigest != b.StartupDigest || !sql.NotBefore.Equal(b.NotBefore) || !sql.NotAfter.Equal(b.NotAfter) {
		return zero, cfg.ErrChanged
	}
	return sql, nil
}

// ReadHandoverProviderMaterial permits only the still-required retirement of
// the two original children. It cannot authorize issuing another credential.
func (s *InitialPreparer) ReadHandoverProviderMaterial(ctx context.Context) (contracts.InitialProviderMaterial, time.Time, error) {
	var zero contracts.InitialProviderMaterial
	_, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	h := w.Activation.Handover
	if h == nil || h.Cleanup == nil || len(h.Cleanup.Steps) < 1 || len(h.Cleanup.Steps) > 2 {
		return zero, time.Time{}, cfg.ErrChanged
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	value, e := s.readProviderMaterial(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	_, _, _, final, e := s.currentHandover(ctx)
	until = identity.Earlier(until, identity.Earlier(final, value.StorageUseUntil))
	if e != nil {
		return zero, time.Time{}, e
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return zero, time.Time{}, e
	}
	return value, until, nil
}
