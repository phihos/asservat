package presentation

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
)

// RecorderPreviewUseCase is the ADR-243 composition preview. The concrete
// ContextInvestigation implements it; an installation without it accepts no
// profile_composition input.
type RecorderPreviewUseCase interface {
	PreviewComposition(context.Context, identities.CurrentIdentity, value.ContextIntent) (app.RecorderPreviewResult, error)
}

// CompositionInput is the runtime subset of capture-composition.schema.json.
// The input schema has already fixed each override's value shape by field.
type CompositionInput struct {
	Components []struct {
		ID         string `json:"id"`
		ProfileRef struct {
			Catalog string `json:"catalog"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"profileRef"`
		Overrides []struct {
			ActionID string          `json:"actionID"`
			Field    string          `json:"field"`
			Value    json.RawMessage `json:"value"`
		} `json:"overrides"`
	} `json:"components"`
	MaxTotalBytes int64  `json:"maxTotalBytes"`
	MaxDuration   string `json:"maxDuration"`
}

type ringInput struct {
	MaxAge            string `json:"maxAge"`
	MaxBytes          int64  `json:"maxBytes"`
	SegmentBytes      int64  `json:"segmentBytes"`
	MaxSegments       int    `json:"maxSegments"`
	Medium            string `json:"medium"`
	StorageProfileRef string `json:"storageProfileRef"`
}

// composition converts typed literal values. Fields whose value types this
// release does not model stay Unmodeled; the compiler refuses them by path.
func (in *CompositionInput) composition() (*planning.ProfileComposition, error) {
	out := &planning.ProfileComposition{MaxTotalBytes: in.MaxTotalBytes, MaxDuration: in.MaxDuration}
	for _, c := range in.Components {
		component := planning.ProfileComponent{ID: c.ID, Profile: planning.ProfileRef{Catalog: c.ProfileRef.Catalog, Name: c.ProfileRef.Name, Version: c.ProfileRef.Version}}
		for _, o := range c.Overrides {
			e := planning.ProfileEdit{ActionID: o.ActionID, Field: o.Field}
			var err error
			switch o.Field {
			case "packetFilter", "packetBefore", "packetAfter", "syscallMode", "syscallBefore", "syscallAfter", "actionTimeout", "actionExecutionMode", "filePath", "profileDuration":
				err = json.Unmarshal(o.Value, &e.Text)
				e.TextSet = err == nil && e.Text == "" // present but empty: the field validator gives the remedy
			case "syscallMaxEvents", "syscallRate", "actionMaxBytes":
				err = json.Unmarshal(o.Value, &e.Number)
			case "packetRing", "syscallRing":
				var r ringInput
				err = json.Unmarshal(o.Value, &r)
				e.Ring = &planning.RingSettings{MaxAge: r.MaxAge, MaxBytes: r.MaxBytes, SegmentBytes: r.SegmentBytes, MaxSegments: r.MaxSegments, Medium: r.Medium, StorageProfileRef: r.StorageProfileRef}
			case "syscallFilter":
				var f struct {
					Mode  string   `json:"mode"`
					Names []string `json:"names"`
				}
				err = json.Unmarshal(o.Value, &f)
				e.Syscalls = &planning.SyscallSelection{Mode: f.Mode, Names: f.Names}
			default:
				e.Unmodeled = true
			}
			if err != nil {
				return nil, err
			}
			component.Edits = append(component.Edits, e)
		}
		out.Components = append(out.Components, component)
	}
	return out, nil
}

// RecorderPreviewData is preview_capture's composition reply (ADR-243). The
// plan is complete and reviewable; capture_enabled is true only for a manual
// network-header plan whose node recorder is available (ADR-248).
type RecorderPreviewData struct {
	PreviewID        string             `json:"preview_id"`
	ExpiresAt        time.Time          `json:"expires_at"`
	ExecutionDigest  string             `json:"execution_digest"`
	PodCount         int                `json:"pod_count"`
	MaxBytes         int64              `json:"max_bytes"`
	MaxProcessStarts int                `json:"max_process_starts"`
	ApprovalRequired bool               `json:"approval_required"`
	CaptureEnabled   bool               `json:"capture_enabled"`
	Blockers         []OperationBlocker `json:"blockers"`
	Warnings         []string           `json:"warnings"`
	NavigationURI    string             `json:"navigation_uri"`
	Composition      json.RawMessage    `json:"profile_composition"`
	Lifecycle        json.RawMessage    `json:"lifecycle_plan"`
	Assessment       CaptureAssessment  `json:"capture_assessment"`
	Target           WorkloadReference  `json:"target_ref"`
	SelectedPods     []SelectedPod      `json:"selected_pods"`
}

// RecorderUnavailableBlocker is the interim blocker of every packet/syscall
// plan, including the explicit onTrigger before:0s variant.
var RecorderUnavailableBlocker = OperationBlocker{Code: "RecorderUnavailable", Message: "Packet and syscall recorders are not installed in this release. This preview shows the reviewed plan only and cannot be submitted.", ResponsibleRole: "administrator", Retryable: false}

func recorderWarnings(plan planning.RecorderPlan) []string {
	out := []string{}
	for _, a := range plan.Actions {
		label := "Packet"
		if a.Kind == "syscallTrace" {
			label = "Syscall"
		}
		if a.ExecutionMode == "ongoing" {
			out = append(out, fmt.Sprintf("%s recording %s starts when the capture is requested and records while armed; no history before the request exists (requested before: %s). It is saved on trigger with %s after.", label, a.ID, a.Before, a.After))
		} else {
			out = append(out, fmt.Sprintf("%s recording %s runs on trigger: it records only the next %s and has no history before it.", label, a.ID, a.After))
		}
		if a.Filter != "" {
			out = append(out, fmt.Sprintf("Packet filter compiled on the hub to %d instructions: %s", a.FilterInstructions, boundedText(a.Filter, 160)))
		}
	}
	return out
}

func boundedText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// RecorderAssessment projects capture-assessment/v1 for a recorder plan,
// after current caller eligibility. It authorizes nothing.
func RecorderAssessment(a planning.RecorderAssessment) CaptureAssessment {
	quantities := func(in []planning.AssessmentQuantity) []Quantity {
		out := make([]Quantity, 0, len(in))
		for _, q := range in {
			out = append(out, Quantity{Dimension: q.Dimension, Phase: q.Phase, Scope: q.Scope, Basis: q.Basis, Lower: q.Lower, Upper: q.Upper, SourceRef: q.SourceRef, Coverage: q.Coverage})
		}
		return out
	}
	basis := AssessmentBasis{RulesDigest: hash(a.RulesDigest), CapabilityDigest: hash(a.CapabilityDigest)}
	basis.Metrics.State = "unavailable"
	out := CaptureAssessment{
		SchemaVersion: "capture-assessment/v1", AssessmentID: a.ID, PlanDigest: hash(a.PlanDigest), GeneratedAt: a.GeneratedAt, ValidUntil: a.ValidUntil,
		Basis: basis, Scope: AssessmentScope{ObservationPods: a.ObservationPods, IncidentPods: a.IncidentPods},
		CombinedImpact:     Impact{a.Combined.Level, a.Combined.HasUnknowns, slices.Clone(a.Combined.Effects), a.Combined.Explanation},
		CombinedQuantities: quantities(a.CombinedQuantities),
		Interactions:       []Interaction{},
		Alternatives:       []Alternative{},
		HandlingCodes:      []string{"minimizeCapture", "restrictAccess", "preferApprovedExtracts", "reviewBeforeSharing", "approvedClientsOnly", "externalCopiesNotRecalled"},
	}
	ids := []string{}
	for _, x := range a.Actions {
		ids = append(ids, x.ActionID)
		r := x.Retention
		policies := make([]string, 0, len(r.PolicyDigests))
		for _, d := range r.PolicyDigests {
			policies = append(policies, hash(d))
		}
		out.Actions = append(out.Actions, AssessmentAction{ActionID: x.ActionID, ExecutionMode: x.ExecutionMode,
			Impact:     Impact{x.Impact.Level, x.Impact.HasUnknowns, slices.Clone(x.Impact.Effects), x.Impact.Explanation},
			Data:       Exposure{x.Exposure.Classification, x.Exposure.Basis, slices.Clone(x.Exposure.RetainedPossible), slices.Clone(x.Exposure.TransientOnly), x.Exposure.UnknownContent},
			Retention:  Retention{"firstAcquisitionOrEarlierSource", r.AccessAgeSeconds, r.DeleteAgeSeconds, r.MaximumAgeSeconds, r.DeletionBudgetSeconds, policies, true, true, "possible"},
			Quantities: quantities(x.Quantities)})
	}
	if a.Interaction != "" {
		out.Interactions = append(out.Interactions, Interaction{ActionIDs: ids, Kind: "sharedPressure", Message: a.Interaction, Blocking: false})
	}
	for _, alt := range a.Alternatives {
		out.Alternatives = append(out.Alternatives, Alternative{ActionIDs: slices.Clone(alt.ActionIDs), Change: alt.Change, Benefit: alt.Benefit, CoverageLoss: alt.CoverageLoss})
	}
	return out
}

func (s *ContextOperations) recorderPreview(ctx context.Context, current identities.CurrentIdentity, in ContextOperationInput) (RecorderPreviewData, time.Time, error) {
	use, ok := s.captures.(RecorderPreviewUseCase)
	if !ok {
		return RecorderPreviewData{}, time.Time{}, value.ErrInvalid
	}
	composition, err := in.Composition.composition()
	if err != nil {
		return RecorderPreviewData{}, time.Time{}, value.ErrInvalid
	}
	result, err := use.PreviewComposition(ctx, current, value.ContextIntent{Target: in.Target.target(), RequestedSeconds: in.RequestedSeconds, Composition: composition})
	if err != nil {
		return RecorderPreviewData{}, time.Time{}, err
	}
	provenance, err := compiler.CompositionProvenance(result.Plan)
	if err != nil {
		return RecorderPreviewData{}, time.Time{}, value.ErrUnavailable
	}
	lifecycle, err := compiler.LifecyclePlanJSON(result.Plan)
	if err != nil {
		return RecorderPreviewData{}, time.Time{}, value.ErrUnavailable
	}
	p := result.Preview
	var limit int64
	for _, a := range result.Plan.Actions {
		limit += a.MaxBytes
	}
	blockers := []OperationBlocker{}
	warnings := recorderWarnings(result.Plan)
	approval := result.Plan.Approval != nil
	// ADR-248: a node recorder runs the plan, except one with REQ-AUT-006
	// observation limits, whose spend it does not charge.
	if !result.Recordable || approval && result.Plan.Approval.ObservationLimits != nil {
		blockers = append(blockers, RecorderUnavailableBlocker)
	} else {
		// ADR-248: the interim per-capture output cap.
		limit = min(limit, artifact.RecordingNativeLimit)
	}
	if approval {
		// ADR-249: an individual approval precedes any observation.
		view := &recorderApprovalView{}
		for _, r := range result.Plan.Approval.Reasons {
			view.reasons = append(view.reasons, r.Code+" ("+r.ActionID+")")
		}
		blockers = append([]OperationBlocker{approvalRequiredBlocker(view)}, blockers...)
		if l := result.Plan.Approval.ObservationLimits; l != nil {
			warnings = append(warnings, fmt.Sprintf("A raw byte comparison may test payload bytes: the approval binds observation limits of %d s per session, %d bytes in total, %d bytes per second and %d concurrent session.", l.MaxSessionSeconds, l.MaxObservedBytes, l.MaxBytesPerSecond, l.MaxConcurrentSessions))
		}
	}
	if !s.config.CollectionEnabled {
		blockers = append(blockers, collectionBlockers(false)...)
	}
	return RecorderPreviewData{PreviewID: p.ID, ExpiresAt: p.Deadline, ExecutionDigest: hash(p.ScopeDigest), PodCount: 1, MaxBytes: limit, CaptureEnabled: len(blockers) == 0, ApprovalRequired: approval, Blockers: blockers,
		Warnings: warnings, NavigationURI: s.config.PublicOrigin + "/captures/new", Composition: provenance, Lifecycle: lifecycle, Assessment: RecorderAssessment(result.Assessment), Target: in.Target,
		SelectedPods: []SelectedPod{{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Name: p.Target.PodName, UID: p.Target.PodUID, Workload: SelectedWorkload{Kind: p.Target.Workload.Kind, Name: p.Target.Workload.Name, UID: p.Target.Workload.UID}}}}, result.ValidUntil, nil
}
