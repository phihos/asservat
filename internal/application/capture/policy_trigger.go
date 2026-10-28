package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
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
	// SettleOccurrences refuses occurrences still open after age as
	// unavailable, without refunding their spend.
	SettleOccurrences(ctx context.Context, age time.Duration) error
}

// occurrenceSettleAge is past any capture attempt: the attempt is bounded at
// 45 s (reviews and continuation pauses included), plus the tick and record,
// with margin.
const occurrenceSettleAge = 2 * time.Minute

// PolicyTrigger polls every active policy's workload for Pod restarts
// (ADR-228), probe failures (ADR-230) or active alerts (ADR-231) and runs one
// supported snapshot or finite onTrigger recorder capture per admitted occurrence. It polls (no watch): each tick costs one
// regional Pod LIST per policy, plus one Event LIST for a probe policy or
// one Alertmanager GET for an alert policy.
// The executor is the policy principal; every check a human capture passes
// still runs, with team authority replacing the human's personal rights.
type PolicyTrigger struct {
	RootID, InstallationID string
	RecipeName             string
	RecipeDigest           artifact.Digest
	CompileRecorder        PolicyRecorderCompiler
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
// next period; it never queues work or retries a capture. Admitted
// occurrences run off the poll loop (ADR-229): at most one capture goroutine
// per policy, so one policy's capture (up to 45 s) never delays the other
// policies' polls. A policy whose previous occurrences are still running is
// not polled this cycle; its next poll coalesces the restarts in between.
// Run returns only after every capture goroutine has finished.
func (t PolicyTrigger) Run(ctx context.Context) error {
	if !t.configured() || ctx == nil {
		return value.ErrUnavailable
	}
	r := &triggerRunner{busy: map[string]bool{}}
	defer r.wg.Wait()
	ticker := time.NewTicker(value.TriggerPollInterval)
	defer ticker.Stop()
	for {
		t.cycle(ctx, r)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// triggerRunner bounds capture goroutines to one per policy and joins them.
type triggerRunner struct {
	wg   sync.WaitGroup
	mu   sync.Mutex
	busy map[string]bool
}

func (r *triggerRunner) running(policy string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.busy[policy]
}

func (r *triggerRunner) start(policy string, work func()) {
	r.mu.Lock()
	r.busy[policy] = true
	r.mu.Unlock()
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			delete(r.busy, policy)
			r.mu.Unlock()
		}()
		work()
	}()
}

// Cycle runs one poll of every active policy, sequentially: the policies of
// one cluster share its regional standby query budget. Its captures run
// inline, before it returns.
func (t PolicyTrigger) Cycle(ctx context.Context) {
	t.cycle(ctx, nil)
}

func (t PolicyTrigger) cycle(ctx context.Context, r *triggerRunner) {
	if !t.configured() || ctx.Err() != nil {
		return
	}
	if err := t.Ledger.SettleOccurrences(ctx, occurrenceSettleAge); err != nil {
		t.report("settle/" + failureClass(err))
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
		if r != nil && r.running(p.PolicyUID) {
			t.report("tick/busy")
			continue
		}
		if err := t.tick(ctx, p, r); err != nil {
			t.report("tick/" + failureClass(err))
		}
	}
}

// Tick observes the policy source and its workload once and runs the
// admitted occurrences. An incomplete observation fires nothing (Unknown).
func (t PolicyTrigger) Tick(ctx context.Context, p value.ActivePolicy) error {
	return t.tick(ctx, p, nil)
}

// tick runs the admitted occurrences inline, or on r's policy goroutine.
func (t PolicyTrigger) tick(ctx context.Context, p value.ActivePolicy, r *triggerRunner) error {
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
	var compiled value.RestartPolicy
	if t.CompileRecorder != nil {
		compiled, err = CompilePolicyWithRecorders(spec, t.RecipeName, t.RecipeDigest, t.CompileRecorder)
	} else {
		compiled, err = CompileRestartPolicy(spec, t.RecipeName, t.RecipeDigest)
	}
	if err != nil {
		return err
	}
	// A finite recorder proceeds through the real preview/admission and typed
	// source/observation start. No ordinary/manual raw path is enabled here.
	accepted, err := t.Accepted.AcceptedPolicyAuthority(tick, p.PolicyUID)
	if err != nil {
		return err
	}
	a := accepted.Authority
	if compiled.Recorder != nil && RecorderPolicyScopeDigest(source.Revision.UID, accepted.IntentVersion, source.CollectionDigest, compiled, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits) != a.ScopeDigest {
		return value.ErrChanged
	}
	if compiled.ClusterID != a.ClusterID {
		return value.ErrChanged
	}
	observation, err := t.Observer.ObserveWorkloadRestarts(tick, compiled.Request())
	if err != nil {
		return err
	}
	if !observation.Answers(compiled.Request()) {
		return value.ErrUnavailable
	}
	if observation.Namespace.UID != a.NamespaceUID || observation.Workload.UID != a.WorkloadUID {
		// A replaced namespace or workload is outside the accepted scope.
		return value.ErrChanged
	}
	occurrences, err := t.Ledger.Tick(tick, value.PolicyTick{Policy: compiled, Authority: a, Observation: observation})
	if err != nil {
		return err
	}
	if len(occurrences) == 0 {
		return nil
	}
	var authored struct {
		Target json.RawMessage `json:"target"`
	}
	if json.Unmarshal(spec, &authored) != nil {
		return value.ErrInvalid
	}
	compiled.HistoryAuthored = &value.HistoryAuthored{Target: targets.WorkloadRequest{ClusterID: compiled.ClusterID, Namespace: compiled.Namespace, Kind: compiled.WorkloadKind, Name: compiled.WorkloadName}, TargetJSON: bytes.Clone(authored.Target), Selector: value.HistorySelector{ClusterID: a.ClusterID, NamespaceUID: a.NamespaceUID, WorkloadKind: compiled.WorkloadKind, WorkloadUID: a.WorkloadUID}, Selection: "triggeringPod", PolicyOrigins: []value.HistoryPolicyOrigin{{UID: source.Revision.UID, Generation: accepted.SourceRevision.Generation, IntentVersion: accepted.IntentVersion, CollectionDigest: source.CollectionDigest}}}
	if !compiled.HistoryAuthored.Valid() {
		return value.ErrChanged
	}
	if r == nil {
		t.run(ctx, a, compiled, observation, occurrences)
	} else {
		r.start(p.PolicyUID, func() { t.run(ctx, a, compiled, observation, occurrences) })
	}
	return nil
}

// run captures each admitted occurrence once, in order, and records it.
func (t PolicyTrigger) run(ctx context.Context, a authorization.AcceptedPolicyAuthority, compiled value.RestartPolicy, observation targets.RestartObservation, occurrences []value.PolicyOccurrence) {
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
		// The outcome is recorded even when Run is shutting down, so a started
		// capture's occurrence is not left open and later settled unavailable.
		record, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := t.Ledger.RecordOccurrence(record, o, captureID, refusal)
		cancel()
		if err != nil {
			t.report("record/" + failureClass(err))
		}
		t.reportTimed("occurrence/"+map[bool]string{true: "captured", false: refusal}[captureID != ""], "in "+time.Since(started).Round(10*time.Millisecond).String()+" ["+times.String()+"]")
	}
}

// capture runs the appropriate snapshot/recorder preview and the ordinary
// request of the triggering Pod under
// the policy executor. The occurrence ID is the idempotency key: the request
// is made once and never repeated after an ambiguous start (ADR-223).
func (t PolicyTrigger) capture(ctx context.Context, a authorization.AcceptedPolicyAuthority, p value.RestartPolicy, o targets.RestartObservation, pod string, occurrence value.PolicyOccurrence) (captureID, refusal string) {
	if pod == "" {
		return "", "unavailable"
	}
	call, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	current := newPolicyIdentity(call, t.Accepted, a, t.Now().Add(45*time.Second), t.Now)
	intent := value.ContextIntent{HistoryAuthored: p.HistoryAuthored.Clone(), Diagnostic: value.ContextDiagnosticName, Target: targets.WorkloadRequest{ClusterID: o.ClusterID, Namespace: o.Namespace.Name, Kind: "Pod", Name: pod}, RequestedSeconds: p.RetentionSeconds}
	if p.Recorder != nil {
		intent.Diagnostic = ""
		intent.Composition = p.Recorder.Composition.Clone()
	}
	// A review that admitted nothing (a lost regional exchange, a replaced
	// standby) is reviewed again, at most three times, two seconds apart, as a
	// human retries a preview. Every review repeats all checks; the occurrence
	// key keeps admission to at most one capture (a second preview under the
	// same key conflicts instead of admitting).
	var err error
	for review := 0; review < 3; review++ {
		if review > 0 && pause(call, 2*time.Second) != nil {
			break
		}
		var id string
		id, err = t.review(call, current, a, intent, occurrence)
		if id != "" {
			return id, ""
		}
		if !retryableReview(err) {
			break
		}
		t.reportTimed("review/"+failureClass(err), "")
	}
	return "", refusalFor(err)
}

// review is one preview and request of the triggering Pod; it returns the
// admitted capture, continuing a start refused before any effect.
func (t PolicyTrigger) review(call context.Context, current policyIdentity, a authorization.AcceptedPolicyAuthority, intent value.ContextIntent, occurrence value.PolicyOccurrence) (string, error) {
	mark := time.Now()
	var preview value.ContextPreview
	var err error
	if intent.Composition != nil {
		recorder, e := t.Capture.PreviewComposition(call, current, intent)
		err = e
		if err == nil && !recorder.Recordable {
			err = value.ErrRecorderUnavailable
		}
		preview = recorder.Preview
	} else {
		snapshot, e := t.Capture.Preview(call, current, intent)
		preview, err = snapshot.Preview, e
	}
	auditapp.MarkStep(call, "policy-preview", mark)
	if err != nil {
		return "", err
	}
	// The named Pod must still be the triggering Pod of the accepted workload:
	// a replacement under the same name is never captured instead.
	if preview.Target.PodUID != occurrence.PodUID || preview.Target.Workload.UID != a.WorkloadUID || preview.Target.Namespace.UID != a.NamespaceUID {
		return "", targets.ErrChanged
	}
	mark = time.Now()
	accepted, err := t.Capture.Request(call, current, preview.ID, occurrence.ID)
	auditapp.MarkStep(call, "policy-request", mark)
	if !authorization.UUID(accepted.CaptureID) {
		return "", err
	}
	// Admitted: the capture exists even if a later phase failed. A start
	// refused before any effect (ADR-212 headroom, a busy standby) is
	// continued through the explicit accepted-only path; durable execution
	// state refuses it after any possible start (ADR-223).
	for attempt := 0; attempt < 3 && err != nil && !errors.Is(err, value.ErrPreparationUncertain) && !errors.Is(err, value.ErrAcquisitionClosed); attempt++ {
		// The refused exchange closes first; the region opens the next
		// standby within about two seconds, as for a human continuation.
		if pause(call, 2*time.Second) != nil {
			break
		}
		mark = time.Now()
		_, err = t.Capture.Continue(call, current, preview.ID, occurrence.ID)
		auditapp.MarkStep(call, "policy-continue", mark)
		if err != nil {
			t.reportTimed("continue/"+failureClass(err), "")
		}
	}
	return accepted.CaptureID, nil
}

// retryableReview is true for a review that may succeed on a fresh exchange;
// refusals of authority, capacity, input, a conflicting earlier admission or
// a replaced Pod are final.
func retryableReview(err error) bool {
	for _, final := range []error{value.ErrDenied, value.ErrCapacity, value.ErrProcessingCoverage, value.ErrInvalid, value.ErrConflict, targets.ErrChanged, targets.ErrDenied} {
		if errors.Is(err, final) {
			return false
		}
	}
	return err != nil
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
