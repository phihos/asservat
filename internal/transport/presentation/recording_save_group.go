package presentation

import (
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

// Parent status retains every admitted child. Configured action IDs are not
// unique across Pods and cannot identify a grouped action instance.
func recordingProgressActions(p value.ContextProgress) ([]ContextActionData, error) {
	if len(p.Actions) == 0 {
		action := p.ActionID
		if action == "" {
			action = "pod-status"
		}
		return []ContextActionData{{ActionID: action, Phase: p.ActionPhase, ReasonCode: p.ReasonCode}}, nil
	}
	if p.Operation != "recordingSave" || len(p.Actions) > value.MaxRecordingSaveGroupChildren {
		return nil, value.ErrUnavailable
	}
	out := make([]ContextActionData, 0, len(p.Actions))
	seen := map[string]bool{}
	for _, a := range p.Actions {
		if !authorization.UUID(a.InstanceID) || a.InstanceID == p.CaptureID || seen[a.InstanceID] || !identity.Text(a.PodUID, 128) || !identity.Text(a.PodName, 253) || !identity.Text(a.ActionID, 63) {
			return nil, value.ErrUnavailable
		}
		seen[a.InstanceID] = true
		out = append(out, ContextActionData{InstanceID: a.InstanceID, PodUID: a.PodUID, PodName: a.PodName, ActionID: a.ActionID, Phase: a.Phase, ReasonCode: a.ReasonCode})
	}
	return out, nil
}

func recordingPreviewSelection(result app.ContextPreviewResult, handles []string) ([]RecordingRow, []RecordingWindow, error) {
	p, m := result.Preview, result.RecordingSave
	if m == nil || len(m.Selected) < 1 || len(m.Selected) > value.MaxRecordingSaveGroupChildren || len(m.Selected) != len(handles) || m.IncidentPodCap < 1 {
		return nil, nil, value.ErrUnavailable
	}
	bounds := map[string]time.Duration{}
	if len(m.Windows) > 0 && len(m.Windows) != len(m.Selected) {
		return nil, nil, value.ErrUnavailable
	}
	if p.Group != nil {
		if len(p.Group.Children) < 2 || p.Intent.Snapshot != nil || len(p.Group.Children) != len(m.Selected) || len(m.Windows) != len(m.Selected) {
			return nil, nil, value.ErrUnavailable
		}
		for _, c := range p.Group.Children {
			key := c.Reference.PodUID + "\x00" + c.Reference.ActionID
			if _, ok := bounds[key]; ok {
				return nil, nil, value.ErrUnavailable
			}
			bounds[key] = c.Request.Before
		}
	} else {
		if p.Intent.Snapshot == nil || m.Before <= 0 || m.Before != p.Intent.Snapshot.Request.Before || len(m.Selected) != 1 {
			return nil, nil, value.ErrUnavailable
		}
	}
	effective := map[string]time.Duration{}
	for _, w := range m.Windows {
		if _, ok := effective[w.Handle]; ok {
			return nil, nil, value.ErrUnavailable
		}
		effective[w.Handle] = w.Before
	}
	rows := make([]RecordingRow, 0, len(m.Selected))
	windows := make([]RecordingWindow, 0, len(m.Selected))
	seen := map[string]bool{}
	pods := map[string]bool{}
	for _, r := range m.Selected {
		if r.Handle == "" || !slices.Contains(handles, r.Handle) || seen[r.Handle] {
			return nil, nil, value.ErrUnavailable
		}
		before := m.Before
		if p.Group != nil || len(m.Windows) > 0 {
			var ok bool
			before, ok = effective[r.Handle]
			if !ok {
				return nil, nil, value.ErrUnavailable
			}
		}
		if before <= 0 || before > r.MaximumBefore {
			return nil, nil, value.ErrUnavailable
		}
		if p.Group != nil && before != bounds[r.PodUID+"\x00"+r.ActionID] {
			return nil, nil, value.ErrUnavailable
		}
		seen[r.Handle] = true
		pods[r.PodUID] = true
		rows = append(rows, recordingRow(r, time.Time{}))
		windows = append(windows, RecordingWindow{r.Handle, artifact.LifecycleDuration(before), "0s"})
	}
	if len(pods) > m.IncidentPodCap {
		return nil, nil, value.ErrUnavailable
	}
	return rows, windows, nil
}
