package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ReadHandover inspects only the protected original root. Missing state is not
// no-effect proof or permission to recreate anything. An existing handover is
// independently checked before callers may select passive historical startup.
func (s *InitialPreparer) ReadHandover(ctx context.Context) (contracts.InitialPreparationRoot, bool, error) {
	var zero contracts.InitialPreparationRoot
	if !s.HandoverEnabled() || ctx == nil {
		return zero, false, cfg.ErrInvalid
	}
	start := s.protection.observer.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	// Fixed step labels name the refusing check for the loader diagnostic;
	// every cause is preserved for errors.Is.
	step := func(name string, e error) error { return &observationStep{"handover-" + name, e} }
	if e := s.creator.administrator(ctx); e != nil {
		return zero, false, step("administrator", e)
	}
	_, bound, e := s.protection.current(ctx)
	until = identity.Earlier(until, bound)
	if e != nil {
		return zero, false, step("protection", e)
	}
	_, w, e := s.read(ctx)
	if apierrors.IsNotFound(e) {
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
			return zero, false, step("absent-deadline", e)
		}
		return zero, false, nil
	}
	if e != nil {
		return zero, false, step("root", e)
	}
	if w.Activation == nil || w.Activation.Handover == nil {
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
			return zero, false, step("active-deadline", e)
		}
		return w, false, nil
	}
	// Read-only: after the guard bridge the retained guard is accepted (ADR-187).
	_, w, _, bound, e = s.passiveHandover(ctx)
	until = identity.Earlier(until, bound)
	if e != nil {
		return zero, false, step("passive", e)
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return zero, false, step("passive-deadline", e)
	}
	return w, true, nil
}

func (s *InitialPreparer) handoverPod(raw []byte, w contracts.InitialPreparationRoot, gated bool) (*core.Pod, error) {
	var pod core.Pod
	a := w.Activation
	if strictGuardJSON(raw, &pod) != nil {
		return nil, cfg.ErrChanged
	}
	metadata := pod.ObjectMeta.DeepCopy()
	annotations := 3
	if pod.Annotations[initialPreparationRetiredAnnotation] != "" {
		if gated || a == nil || a.Handover == nil || a.Handover.Cleanup == nil || len(a.Handover.Cleanup.Steps) < 7 || pod.Annotations[initialPreparationRetiredAnnotation] != a.Pod.Receipt.UID {
			return nil, cfg.ErrChanged
		}
		annotations = 4
		metadata.DeletionTimestamp = nil
	}
	if a == nil || a.Pod == nil || a.Pod.Receipt == nil || strictGuardJSON(raw, &pod) != nil || permissionJSON(raw, 64<<10, 16384) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || !s.creator.owns(*metadata, s.plan.Workload.Name) || pod.Namespace != s.plan.Workload.Namespace || string(pod.UID) != a.Pod.Receipt.UID || len(pod.Annotations) != annotations || pod.Annotations[initialPreparationOperationAnnotation] != a.Pod.OperationID || len(pod.OwnerReferences) != 0 || len(pod.Finalizers) != 0 {
		return nil, cfg.ErrChanged
	}
	if gated {
		if _, _, e := s.verifiedGatedPod(raw, *a.Pod); e != nil {
			return nil, e
		}
	} else {
		digest, e := initialPreparationDigest(a.Pod.SpecDigest)
		if e != nil || len(pod.Spec.SchedulingGates) != 0 || InstallationPodSpecDigest(pod.Spec) != digest {
			return nil, cfg.ErrChanged
		}
		want, e := BuildInitialInstallerWorkload(preparerWorkload(s.plan))
		if e != nil || !equalJSON(pod.Labels, want.Pod.Labels) {
			return nil, cfg.ErrChanged
		}
	}
	return &pod, nil
}

// LaunchOriginalPod permits one original UPDATE and at most one retry after its
// durably acknowledged exact API conflict. A retained retry or unknown original
// outcome permits observation only.
// Original Pod, credential and claim dates never change on resumed calls.
func (s *InitialPreparer) LaunchOriginalPod(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	cm, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, e
	}
	h := w.Activation.Handover
	if h == nil || h.Staging == nil || h.Staging.Receipt == nil {
		return zero, cfg.ErrChanged
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	path := "/api/v1/namespaces/" + s.plan.Workload.Namespace + "/pods/" + s.plan.Workload.Name
	raw, e := s.creator.raw(ctx, path, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	fresh := false
	var pod *core.Pod
	if h.Launch == nil {
		pod, e = s.handoverPod(raw, w, true)
		if e != nil {
			return zero, e
		}
		now := s.protection.observer.now().UTC().Truncate(time.Microsecond)
		if now.Before(w.Activation.Credentials.NotBefore) || !now.Before(w.Activation.Credentials.NotAfter) {
			return zero, cfg.ErrUnavailable
		}
		// The original private projection contains the positively verified provider
		// and API probe responses. Reading it cannot issue or adopt replacements.
		_, private, e := s.readPrivate(ctx)
		if e != nil || private.RootUID != w.RootUID || private.Providers == nil || private.Providers.Wrap == nil || private.Providers.Wrap.Response == nil || private.Providers.Unwrap == nil || private.Providers.Unwrap.Response == nil || private.Probe == nil || private.Probe.Issue == nil || private.Probe.Issue.Response == nil {
			return zero, cfg.ErrChanged
		}
		until = identity.Earlier(until, w.Activation.Credentials.NotAfter)
		until = identity.Earlier(until, private.Providers.Wrap.Response.ExpiresAt)
		until = identity.Earlier(until, private.Providers.Unwrap.Response.ExpiresAt)
		until = identity.Earlier(until, private.Probe.Issue.Response.ExpiresAt)
		until = until.UTC().Truncate(time.Microsecond)
		if !initialHandoverInterval(now, until) {
			return zero, cfg.ErrUnavailable
		}
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		h.Launch = &contracts.InitialPreparationLaunch{ID: id, PodResourceVersion: pod.ResourceVersion, StartedAt: now, Until: until}
		if e = s.handoverWrite(ctx, cm, w, until); e != nil {
			return zero, e
		}
		fresh = true
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, e
		}
		h = w.Activation.Handover
	}
	if !fresh {
		cm, w, e = s.persistHandoverConflict(ctx, cm, w, "launch", until)
		if e != nil {
			return zero, e
		}
		h = w.Activation.Handover
	}
	if fresh {
		effect, done := context.WithDeadline(ctx, h.Launch.Until)
		defer done()
		if e = initialHandoverDeadline(effect, s.protection.observer.now, h.Launch.Until); e != nil {
			return zero, e
		}
		pod.Spec.SchedulingGates = nil
		raw, e = json.Marshal(pod)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		var status int
		raw, status, e = s.conditionalHandoverPut(effect, path, raw)
		if e != nil {
			if !s.retainHandoverConflict(effect, w, "launch", raw, status) {
				return zero, cfg.ErrUnavailable
			}
			cm, w, e = s.persistHandoverConflict(effect, cm, w, "launch", until)
			if e != nil {
				return zero, e
			}
			h = w.Activation.Handover
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, h.Launch.Until); e != nil {
			return zero, e
		}
	}
	if h.Launch.FirstConflict != nil && h.Launch.Retry == nil {
		until = identity.Earlier(until, h.Launch.Until)
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
			return zero, e
		}
		effect, done := context.WithDeadline(ctx, until)
		defer done()
		raw, e = s.creator.raw(effect, path, nil)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		pod, e = s.handoverPod(raw, w, true)
		if e != nil || pod.ResourceVersion == h.Launch.PodResourceVersion {
			return zero, cfg.ErrChanged
		}
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		h.Launch.Retry = &contracts.InitialPreparationConditionalRetry{ID: id, ResourceVersion: pod.ResourceVersion, ClaimedAt: s.protection.observer.now().UTC().Truncate(time.Microsecond)}
		if e = s.handoverWrite(effect, cm, w, until); e != nil {
			return zero, e
		}
		// Only this acknowledged CAS owner sends the second UPDATE. Reading a
		// retained retry claim never permits a third or resumed invocation.
		cm, w, e = s.read(effect)
		if e != nil {
			return zero, e
		}
		h = w.Activation.Handover
		if h.Launch.Retry == nil || h.Launch.Retry.ID != id || h.Launch.Retry.ResourceVersion != pod.ResourceVersion {
			return zero, cfg.ErrChanged
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, until); e != nil {
			return zero, e
		}
		pod.Spec.SchedulingGates = nil
		raw, e = json.Marshal(pod)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		raw, _, e = s.conditionalHandoverPut(effect, path, raw)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		if e = initialHandoverDeadline(effect, s.protection.observer.now, until); e != nil {
			return zero, e
		}
	}
	if _, e = s.handoverPod(raw, w, false); e != nil {
		return zero, e
	}
	if h.Launch.Observed {
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
			return zero, e
		}
		return w, nil
	}
	h.Launch.Observed = true
	// Exact late observation acknowledges only the original transition; it does
	// not renew the launch interval or imply successful installation.
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}

// InitialPreparationPodDisposition is current observation of the exact original
// Pod. A successful process is not SQL activation or proof of provider cleanup.
type InitialPreparationPodDisposition struct {
	Phase      core.PodPhase
	Terminated bool
	ExitCode   int32
	ValidUntil time.Time
}

func (s *InitialPreparer) ObserveOriginalActivation(ctx context.Context) (contracts.InitialPreparationRoot, InitialPreparationPodDisposition, error) {
	var zero contracts.InitialPreparationRoot
	var none InitialPreparationPodDisposition
	_, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, none, e
	}
	if w.Activation.Handover == nil || w.Activation.Handover.Launch == nil || !w.Activation.Handover.Launch.Observed {
		return zero, none, cfg.ErrChanged
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/pods/"+s.plan.Workload.Name, nil)
	if e != nil {
		return zero, none, cfg.ErrUnavailable
	}
	pod, e := s.handoverPod(raw, w, false)
	if e != nil {
		return zero, none, e
	}
	out := InitialPreparationPodDisposition{Phase: pod.Status.Phase, ValidUntil: until}
	if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
		if len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].Name != pod.Spec.Containers[0].Name || pod.Status.ContainerStatuses[0].State.Terminated == nil || pod.Status.ContainerStatuses[0].RestartCount != 0 || len(pod.Status.InitContainerStatuses) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
			return zero, none, cfg.ErrUnavailable
		}
		terminal := pod.Status.ContainerStatuses[0].State.Terminated
		if !initialPreparationTerminalTimes(terminal.StartedAt.Time, terminal.FinishedAt.Time, w.Activation.Handover.Launch.StartedAt, s.protection.observer.now()) {
			return zero, none, cfg.ErrChanged
		}
		out.Terminated = true
		out.ExitCode = terminal.ExitCode
	}
	_, _, _, final, e := s.currentHandover(ctx)
	out.ValidUntil = identity.Earlier(until, final)
	if e != nil {
		return zero, none, e
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, out.ValidUntil); e != nil {
		return zero, none, e
	}
	return w, out, nil
}

// metav1.Time is serialized at whole-second precision. This helper compares
// observational ordering only; original microsecond authority/claim deadlines
// are never rounded or extended. The exact Pod UID and full spec remain bound.
func initialPreparationTerminalTimes(started, finished, launch, now time.Time) bool {
	if started.IsZero() || finished.IsZero() || launch.IsZero() || now.IsZero() {
		return false
	}
	return !finished.Before(started) && !started.Before(launch.Truncate(time.Second)) && !finished.After(now.Truncate(time.Second))
}
