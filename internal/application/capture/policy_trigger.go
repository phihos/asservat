package capture

import (
	"context"
	"errors"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicyTriggerLedger is the trigger ledger (watermarks, occurrences,
// budgets, spend and suppression). An occurrence is not a permit.
type PolicyTriggerLedger interface {
	ActivePolicies(context.Context) ([]value.ActivePolicy, error)
	Tick(context.Context, value.PolicyTick) ([]value.PolicyOccurrence, error)
	RecordOccurrence(ctx context.Context, o value.PolicyOccurrence, captureID, refusal string) error
}

// PolicyTrigger polls every active policy's workload for Pod restarts and
// runs one ordinary pod-status capture per admitted occurrence (ADR-228).
// It polls (no watch): each tick costs one regional Pod LIST per policy.
// The executor is the policy principal; every check a human capture passes
// still runs, with team authority replacing the human's personal rights.
type PolicyTrigger struct {
	RootID, InstallationID string
	RecipeName             string
	RecipeDigest           artifact.Digest
	Ledger                 PolicyTriggerLedger
	Documents              PolicyDocuments
	Sources                PolicySourceWriter
	Accepted               authapp.AcceptedPolicyReader
	Observer               RestartObserver
	Capture                ContextSubmission
	Audit                  PolicyAuditPublisher
	Now                    func() time.Time
	// Report receives a fixed outcome label and producer-owned step timings;
	// diagnostics, never authority.
	Report func(event, timing string)
}

func (t PolicyTrigger) configured() bool {
	return authorization.UUID(t.RootID) && authorization.UUID(t.InstallationID) && t.RecipeName != "" && t.RecipeDigest != (artifact.Digest{}) && t.Ledger != nil && t.Documents != nil && t.Sources != nil && t.Accepted != nil && t.Observer != nil && t.Audit != nil && t.Now != nil && t.Capture.ContextInvestigation.configured() && t.Capture.Intents != nil && t.Capture.Start != nil
}

func (t PolicyTrigger) report(label string) {
	t.reportTimed(label, "")
}

func (t PolicyTrigger) reportTimed(label, timing string) {
	if t.Report != nil {
		t.Report(label, timing)
	}
}

// Run polls until ctx ends. A failed tick is reported and retried on the
// next period; it never queues work or retries a capture.
func (t PolicyTrigger) Run(ctx context.Context) error {
	if !t.configured() || ctx == nil {
		return value.ErrUnavailable
	}
	ticker := time.NewTicker(value.TriggerPollInterval)
	defer ticker.Stop()
	for {
		t.Cycle(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Cycle runs one poll of every active policy, sequentially: the policies of
// one cluster share its regional standby query budget.
func (t PolicyTrigger) Cycle(ctx context.Context) {
	if !t.configured() || ctx.Err() != nil {
		return
	}
	if err := t.Audit.PublishPolicyAcceptances(ctx); err != nil {
		t.report("audit/" + failureClass(err))
	}
	policies, err := t.Ledger.ActivePolicies(ctx)
	if err != nil {
		t.report("list/" + failureClass(err))
		return
	}
	for _, p := range policies {
		if ctx.Err() != nil {
			return
		}
		if err := t.Tick(ctx, p); err != nil {
			t.report("tick/" + failureClass(err))
		}
	}
}

// Tick observes the policy source and its workload once and runs the
// admitted occurrences. An incomplete observation fires nothing (Unknown).
func (t PolicyTrigger) Tick(ctx context.Context, p value.ActivePolicy) error {
	tick, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	source, spec, err := t.Documents.ReadPolicy(tick, p.Name, p.PolicyUID)
	if err != nil {
		return err
	}
	if err = t.Sources.ObservePolicy(tick, source); err != nil {
		return err
	}
	if source.Suspended || source.Deleted {
		return nil
	}
	compiled, err := CompileRestartPolicy(spec, t.RecipeName, t.RecipeDigest)
	if err != nil {
		return err
	}
	accepted, err := t.Accepted.AcceptedPolicyAuthority(tick, p.PolicyUID)
	if err != nil {
		return err
	}
	a := accepted.Authority
	if compiled.ClusterID != a.ClusterID {
		return value.ErrChanged
	}
	observation, err := t.Observer.ObserveWorkloadRestarts(tick, targets.WorkloadRequest{ClusterID: compiled.ClusterID, Namespace: compiled.Namespace, Kind: compiled.WorkloadKind, Name: compiled.WorkloadName})
	if err != nil {
		return err
	}
	if observation.Namespace.UID != a.NamespaceUID || observation.Workload.UID != a.WorkloadUID {
		// A replaced namespace or workload is outside the accepted scope.
		return value.ErrChanged
	}
	occurrences, err := t.Ledger.Tick(tick, value.PolicyTick{Policy: compiled, Authority: a, Observation: observation})
	if err != nil {
		return err
	}
	for _, o := range occurrences {
		var name string
		for _, pod := range observation.Pods {
			if pod.UID == o.PodUID {
				name = pod.Name
			}
		}
		timed, times := auditapp.WithStepTimes(ctx)
		started := time.Now()
		captureID, refusal := t.capture(timed, a, compiled, observation, name, o)
		if err := t.Ledger.RecordOccurrence(ctx, o, captureID, refusal); err != nil {
			t.report("record/" + failureClass(err))
		}
		t.reportTimed("occurrence/"+map[bool]string{true: "captured", false: refusal}[captureID != ""], "in "+time.Since(started).Round(10*time.Millisecond).String()+" ["+times.String()+"]")
	}
	return nil
}

// capture runs the ordinary preview and request of the triggering Pod under
// the policy executor. The occurrence ID is the idempotency key: the request
// is made once and never repeated after an ambiguous start (ADR-223).
func (t PolicyTrigger) capture(ctx context.Context, a authorization.AcceptedPolicyAuthority, p value.RestartPolicy, o targets.RestartObservation, pod string, occurrence value.PolicyOccurrence) (captureID, refusal string) {
	if pod == "" {
		return "", "unavailable"
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	current := newPolicyIdentity(call, t.Accepted, a, t.Now().Add(30*time.Second), t.Now)
	intent := value.ContextIntent{Diagnostic: value.ContextDiagnosticName, Target: targets.WorkloadRequest{ClusterID: o.ClusterID, Namespace: o.Namespace.Name, Kind: "Pod", Name: pod}, RequestedSeconds: p.RetentionSeconds}
	mark := time.Now()
	preview, err := t.Capture.Preview(call, current, intent)
	auditapp.MarkStep(call, "policy-preview", mark)
	if err != nil {
		return "", refusalFor(err)
	}
	// The named Pod must still be the triggering Pod of the accepted workload:
	// a replacement under the same name is never captured instead.
	if preview.Preview.Target.PodUID != occurrence.PodUID || preview.Preview.Target.Workload.UID != a.WorkloadUID || preview.Preview.Target.Namespace.UID != a.NamespaceUID {
		return "", "unavailable"
	}
	mark = time.Now()
	accepted, err := t.Capture.Request(call, current, preview.Preview.ID, occurrence.ID)
	auditapp.MarkStep(call, "policy-request", mark)
	if authorization.UUID(accepted.CaptureID) {
		// Admitted: the capture exists even if a later phase failed. A start
		// refused before any effect (ADR-212 headroom, a busy standby) is
		// continued once through the explicit accepted-only path; durable
		// execution state refuses it after any possible start (ADR-223).
		for attempt := 0; attempt < 3 && err != nil && !errors.Is(err, value.ErrPreparationUncertain) && !errors.Is(err, value.ErrAcquisitionClosed); attempt++ {
			// The refused exchange closes first; the region opens the next
			// standby within about two seconds, as for a human continuation.
			if pause(call, 2*time.Second) != nil {
				break
			}
			mark = time.Now()
			_, err = t.Capture.Continue(call, current, preview.Preview.ID, occurrence.ID)
			auditapp.MarkStep(call, "policy-continue", mark)
			if err != nil {
				t.reportTimed("continue/"+failureClass(err), "")
			}
		}
		return accepted.CaptureID, ""
	}
	return "", refusalFor(err)
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func refusalFor(err error) string {
	switch {
	case errors.Is(err, value.ErrCapacity), errors.Is(err, value.ErrProcessingCoverage):
		return "capacity"
	case errors.Is(err, value.ErrDenied):
		return "authority"
	default:
		return "unavailable"
	}
}

func failureClass(err error) string {
	for _, c := range []struct {
		name string
		err  error
	}{{"invalid", value.ErrInvalid}, {"denied", value.ErrDenied}, {"changed", value.ErrChanged}, {"capacity", value.ErrCapacity}, {"conflict", value.ErrConflict}, {"unavailable", value.ErrUnavailable}, {"target-limit", targets.ErrLimit}, {"target-changed", targets.ErrChanged}, {"target-unavailable", targets.ErrUnavailable}} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "other"
}
