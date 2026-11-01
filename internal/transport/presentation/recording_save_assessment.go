package presentation

import (
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"slices"
)

// A Save projects each source's assessed snapshot increment. It does not reuse
// pod-status labels or turn the ongoing recorder baseline into measured cost.
func recordingSaveAssessment(result app.ContextPreviewResult) (CaptureAssessment, error) {
	m := result.RecordingSave
	if m == nil || len(m.Selected) < 1 || len(m.Selected) > value.MaxRecordingSaveGroupChildren {
		return CaptureAssessment{}, value.ErrUnavailable
	}
	assessments := m.Assessments
	if len(assessments) == 0 && result.Preview.Group == nil && len(m.Selected) == 1 {
		row := m.Selected[0]
		assessments = []app.RecordingSaveActionAssessment{{ActionID: row.ActionID, PodUID: row.PodUID, Assessment: result.Assessment}}
	}
	if len(assessments) != len(m.Selected) {
		return CaptureAssessment{}, value.ErrUnavailable
	}
	out := ContextAssessment(result.Assessment)
	out.Actions = make([]AssessmentAction, 0, len(assessments))
	seen := map[string]bool{}
	pods := map[string]bool{}
	actionIDs := []string{}
	var total int64
	for _, a := range assessments {
		var row *app.RecordingRow
		for i := range m.Selected {
			candidate := &m.Selected[i]
			if candidate.PodUID == a.PodUID && candidate.ActionID == a.ActionID {
				if row != nil {
					return CaptureAssessment{}, value.ErrUnavailable
				}
				row = candidate
			}
		}
		if row == nil || row.Handle == "" || seen[row.Handle] || a.Assessment.OutputLimit <= 0 || a.Assessment.OutputLimit > artifact.RecordingNativeLimit {
			return CaptureAssessment{}, value.ErrUnavailable
		}
		seen[row.Handle] = true
		pods[row.PodUID] = true
		total += a.Assessment.OutputLimit
		projected := ContextAssessment(a.Assessment).Actions[0]
		projected.RecordingHandle = row.Handle
		projected.ActionID = a.ActionID
		projected.ExecutionMode = "ongoing"
		projected.Retention.AnchorRule = "firstAcquisitionOrEarlierSource"
		projected.Quantities = []Quantity{{Dimension: "outputBytes", Phase: "perIncident", Scope: "perIncidentPod", Basis: "configuredLimit", Lower: 0, Upper: a.Assessment.OutputLimit, SourceRef: "existing-source-window", Coverage: "Configured native snapshot output only; object/encryption overhead and total collector memory are separate. Ongoing source costs are not added by this Save."}}
		out.Actions = append(out.Actions, projected)
		if !slices.Contains(actionIDs, a.ActionID) {
			actionIDs = append(actionIDs, a.ActionID)
		}
	}
	if total != result.Assessment.OutputLimit {
		return CaptureAssessment{}, value.ErrUnavailable
	}
	out.Scope = AssessmentScope{ObservationPods: 0, IncidentPods: len(pods)}
	out.CombinedQuantities = []Quantity{{Dimension: "outputBytes", Phase: "perIncident", Scope: "wholePlan", Basis: "configuredLimit", Lower: 0, Upper: total, SourceRef: "recording-save/v1", Coverage: "Sum of independently bounded native snapshot outputs. Ongoing recording, encryption/object overhead and total collector memory are not measured by this preview."}}
	out.Interactions = []Interaction{{ActionIDs: actionIDs, Kind: "sharedPressure", Message: "Snapshot copying, encryption and upload can share resources. Current pressure and the continuing recorder baseline are not measured by this preview.", Blocking: false}}
	return out, nil
}
