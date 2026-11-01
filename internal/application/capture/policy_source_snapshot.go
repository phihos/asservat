package capture

import (
	"context"
	"errors"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

func (t PolicyTrigger) captureSourceSnapshot(ctx context.Context, current identities.CurrentIdentity, a authorization.AcceptedPolicyAuthority, p value.RestartPolicy, o targets.RestartObservation, pod string, occurrence value.PolicyOccurrence) (string, string) {
	if t.SourceSnapshots == nil || t.OngoingSources == nil || t.OngoingSources.Ledger == nil || p.Recorder == nil || occurrence.TriggeredAt.IsZero() {
		return "", "unavailable"
	}
	rows, err := t.OngoingSources.Ledger.ListSources(ctx, a.PolicyUID)
	if err != nil {
		return "", refusalFor(err)
	}
	// ADR-275: the first recorder's capture is the occurrence's outcome; each
	// further recorder's capture is its own idempotent child of the occurrence.
	captureID, refusal := t.snapshotRecorder(ctx, current, a, p, o, pod, occurrence, rows, p.Recorder.Action.ID, occurrence.ID)
	for _, r := range p.MoreRecorders {
		if _, childRefusal := t.snapshotRecorder(ctx, current, a, p, o, pod, occurrence, rows, r.Action.ID, value.OccurrenceCaptureKey(occurrence.ID, r.Action.ID)); childRefusal != "" {
			t.report("occurrence-child/" + childRefusal)
		}
	}
	return captureID, refusal
}

// snapshotRecorder captures one recorder's source window of the triggering
// Pod under key: the occurrence ID, or a further recorder's derived key.
func (t PolicyTrigger) snapshotRecorder(ctx context.Context, current identities.CurrentIdentity, a authorization.AcceptedPolicyAuthority, p value.RestartPolicy, o targets.RestartObservation, pod string, occurrence value.PolicyOccurrence, rows []PolicySourceState, action, key string) (string, string) {
	var selected *PolicySourceState
	for n := range rows {
		row := &rows[n]
		if row.Binding.PodUID == occurrence.PodUID && row.Binding.ActionID == action && row.Binding.Scope == [32]byte(a.ScopeDigest) {
			if selected != nil {
				return "", "unavailable"
			}
			selected = row
		}
	}
	if selected == nil || selected.Target == nil || selected.Target.Request.PodName != pod || selected.Target.Request.ClusterID != o.ClusterID || selected.Target.Request.Namespace != o.Namespace || selected.Target.Request.Workload != o.Workload {
		return "", "unavailable"
	}
	preview, err := t.SourceSnapshots.PreviewPolicySnapshot(ctx, current, PolicySnapshotSelection{Policy: p, Authority: a, Source: *selected, Target: selected.Target.Request, TriggeredAt: occurrence.TriggeredAt})
	if err != nil {
		// The closed refusal is the recorded outcome; the fixed preview
		// stage only names where it failed.
		t.reportStage("occurrence-preview", err)
		return "", refusalFor(err)
	}
	if preview.Preview.Target.PodUID != occurrence.PodUID || preview.Preview.Actor != a.Executor || preview.Preview.Intent.Snapshot == nil || !preview.Preview.Intent.Snapshot.Request.T0.Equal(occurrence.TriggeredAt) {
		t.report("occurrence-preview/mismatch")
		return "", "unavailable"
	}
	admitted, err := t.SourceSnapshots.Request(ctx, current, preview.Preview.ID, key)
	if authorization.UUID(admitted.CaptureID) {
		return admitted.CaptureID, ""
	}
	t.reportStage("occurrence-request", err)
	return "", refusalFor(err)
}

// reportStage names where a policy snapshot was refused: the fixed stage of
// a labeled failure, else its class. The closed refusal is the outcome.
func (t PolicyTrigger) reportStage(prefix string, err error) {
	var fixed interface{ FixedStep() string }
	if errors.As(err, &fixed) {
		t.report(prefix + "/" + fixed.FixedStep())
		return
	}
	t.report(prefix + "/" + failureClass(err))
}
