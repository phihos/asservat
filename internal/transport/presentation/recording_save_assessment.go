package presentation

import (
	"fmt"
	"slices"

	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

// recordingSavePreview projects a Save of existing recordings onto the
// preview_capture reply (REQ-SAV-004): policy-armed sources, each saved with
// its window before the request and nothing after.
func (s *ContextOperations) recordingSavePreview(result app.ContextPreviewResult, handles []string) (ContextPreviewData, error) {
	p, m := result.Preview, result.RecordingSave
	if m == nil || p.ScopeDigest != result.Assessment.PlanDigest || !s.config.Now().Before(p.SelectionUntil) {
		return ContextPreviewData{}, value.ErrUnavailable
	}
	rows, windows, err := recordingPreviewSelection(result, handles)
	if err != nil {
		return ContextPreviewData{}, err
	}
	assessment, err := recordingSaveAssessment(result)
	if err != nil {
		return ContextPreviewData{}, err
	}
	lifecycle := LifecyclePlan{SchemaVersion: "action-lifecycle/v1", RequestKind: "DebugPolicy", Actions: []LifecycleAction{}, OngoingPodScope: "none"}
	warnings := sharingWarning(p.Intent.Sharing)
	pods := map[string]bool{}
	for i, row := range rows {
		pods[row.PodUID] = true
		action := LifecycleAction{ActionID: row.ActionID, Kind: row.Kind, ExecutionMode: "ongoing", Activation: "policyArming", RequestedBefore: windows[i].Before, After: "0s"}
		if !slices.Contains(lifecycle.Actions, action) {
			lifecycle.Actions = append(lifecycle.Actions, action)
		}
		warnings = append(warnings, fmt.Sprintf("Saves the last %s of recording %s on pod %s. It starts no recorder and runs none of the policy's other actions.", windows[i].Before, row.ActionID, row.PodName))
	}
	enabled := s.config.CollectionEnabled && s.recordingSaveCollection
	data := ContextPreviewData{ExecutionDigest: hash(p.ScopeDigest), PodCount: len(pods), MaxBytes: result.Assessment.OutputLimit, CaptureEnabled: enabled, Blockers: collectionBlockers(enabled), Warnings: warnings, NavigationURI: s.config.PublicOrigin + "/captures/new", Lifecycle: lifecycle, Assessment: assessment}
	if p.Intent.RepeatedFrom != nil && p.Intent.RepeatedFrom.Valid(s.config.Now()) {
		data.RepeatedFrom = p.Intent.RepeatedFrom.CaptureID
	}
	return data, nil
}

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
