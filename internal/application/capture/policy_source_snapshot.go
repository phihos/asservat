package capture

import (
	"context"

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
	var selected *PolicySourceState
	for n := range rows {
		row := &rows[n]
		if row.Binding.PodUID == occurrence.PodUID && row.Binding.ActionID == p.Recorder.Action.ID && row.Binding.Scope == [32]byte(a.ScopeDigest) {
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
		return "", refusalFor(err)
	}
	if preview.Preview.Target.PodUID != occurrence.PodUID || preview.Preview.Actor != a.Executor || preview.Preview.Intent.Snapshot == nil || !preview.Preview.Intent.Snapshot.Request.T0.Equal(occurrence.TriggeredAt) {
		return "", "unavailable"
	}
	admitted, err := t.SourceSnapshots.Request(ctx, current, preview.Preview.ID, occurrence.ID)
	if authorization.UUID(admitted.CaptureID) {
		return admitted.CaptureID, ""
	}
	return "", refusalFor(err)
}
