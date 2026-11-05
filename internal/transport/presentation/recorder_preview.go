package presentation

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/conversion"
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
type CompositionInput contracts.CaptureComposition

func (in *CompositionInput) composition() (*planning.ProfileComposition, error) {
	return conversion.CompositionFromWire(contracts.CaptureComposition(*in))
}

// RecorderPreviewData is preview_capture's composition reply (ADR-243). The
// plan is complete and reviewable; capture_enabled is true only for a manual
// network-header plan whose node recorder is available (ADR-248).
type RecorderResultAccessAction struct {
	ActionID   string   `json:"action_id"`
	Operations []string `json:"operations"`
}

type RecorderPreviewData struct {
	ResultAccessActions []RecorderResultAccessAction `json:"result_access_actions,omitempty"`
	RepeatedFrom        string                       `json:"repeated_from_capture_id,omitempty"`
	PreviewID           string                       `json:"preview_id"`
	ExpiresAt           time.Time                    `json:"expires_at"`
	ExecutionDigest     string                       `json:"execution_digest"`
	PodCount            int                          `json:"pod_count"`
	MaxBytes            int64                        `json:"max_bytes"`
	MaxProcessStarts    int                          `json:"max_process_starts"`
	ApprovalRequired    bool                         `json:"approval_required"`
	CaptureEnabled      bool                         `json:"capture_enabled"`
	Blockers            []OperationBlocker           `json:"blockers"`
	Warnings            []string                     `json:"warnings"`
	NavigationURI       string                       `json:"navigation_uri"`
	Composition         json.RawMessage              `json:"profile_composition"`
	Lifecycle           json.RawMessage              `json:"lifecycle_plan"`
	Assessment          CaptureAssessment            `json:"capture_assessment"`
	Target              WorkloadReference            `json:"target_ref"`
	SelectedPods        []SelectedPod                `json:"selected_pods"`
}

// RecorderUnavailableBlocker is the interim blocker of every packet/syscall
// plan, including the explicit onTrigger before:0s variant.
var RecorderUnavailableBlocker = OperationBlocker{Code: "RecorderUnavailable", Message: "No recorder is available for this reviewed plan. This preview shows the plan only and cannot be submitted.", ResponsibleRole: "administrator", Retryable: false}

func recorderWarnings(plan planning.RecorderPlan) []string {
	out := []string{}
	for _, a := range plan.Actions {
		if a.Kind == "processSnapshot" {
			out = append(out, "This snapshot records process identity and status once, without arguments, environment or memory. Runtime and socket ownership are reported only where qualified.")
			continue
		}
		if a.Kind == "logs" {
			out = append(out, "Logs preserve raw bytes from available current and previous container sources. Streams are combined; requested history may be incomplete and source timestamps may be unknown.")
			if plan.Approval == nil {
				out = append(out, "After collection, request separate approval from the saved artifact for log queries or native download. This observe capture does not include result-access approval.")
			}
			continue
		}
		if a.Kind == "profile" {
			timing := a.ProfileMode
			if a.Duration != "" {
				timing += " for " + a.Duration
			}
			out = append(out, fmt.Sprintf("%s %s profile (%s) runs only after the capture is requested; it provides no pre-trigger history. Native output is raw evidence and live profiling requires approval.", a.ProfileRuntime, a.ProfileType, timing))
			for _, endpoint := range plan.Input.Endpoints {
				if a.EndpointDigest == "" || hash(endpoint.EndpointDigest) != a.EndpointDigest {
					continue
				}
				out = append(out, fmt.Sprintf("Endpoint %s: %s, TCP port %d, %s. Resolved at preview without probing; execution must recheck the reviewed definition and target.", boundedText(endpoint.SourceName, 63), endpoint.AddressMode, endpoint.Port, endpoint.PathPolicy))
			}
			continue
		}
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
			if a.PeerEndpoints > 0 {
				out = append(out, fmt.Sprintf("Peers: %d Kubernetes endpoints resolved at preview (members digest %s), %d prefixes in total, intersected with the packet filter; traffic to or from other addresses is not recorded. Membership is frozen at preview and shown for review.", a.PeerEndpoints, boundedText(a.PeerMembersDigest, 16), a.PeerPrefixes))
				// ADR-283 part 3 (within the 256-character warning bound).
				out = append(out, "Kubernetes peers are checked again at request and start and every second while recording; a removed or reassigned member, or no confirmation within maxStaleness, stops it without a refund.")
			} else if a.PeerPrefixes > 0 {
				out = append(out, fmt.Sprintf("Peers: %d CIDR prefixes, intersected with the packet filter; traffic to or from other addresses is not recorded.", a.PeerPrefixes))
			}
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
			Retention:  Retention{"submissionPreparation", r.AccessAgeSeconds, r.DeleteAgeSeconds, r.MaximumAgeSeconds, r.DeletionBudgetSeconds, policies, true, true, "possible"},
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
	return s.recorderPreviewResult(result, in.Target)
}
func (s *ContextOperations) recorderPreviewResult(result app.RecorderPreviewResult, target WorkloadReference) (RecorderPreviewData, time.Time, error) {
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
	// ADR-248: a node recorder runs the plan. Of the plans with REQ-AUT-006
	// observation limits only a single manual rawPackets or httpHeaders
	// action has an observation issuer, its approved ad hoc grant's pool
	// (ADR-279/282).
	metered := approval && result.Plan.Approval.ObservationLimits != nil
	if !result.Recordable || metered && !compiler.ManualObservationIssued(result.Plan.Actions, result.Plan.Approval) {
		// ADR-283 part 3: a frozen Kubernetes peer plan is recordable like any
		// other; a plan-only one has the generic reason.
		blockers = append(blockers, RecorderUnavailableBlocker)
	} else {
		// Finite logs use the streaming logs ceiling; the original packet/
		// syscall recorders retain their single-frame output ceiling.
		maximum := int64(artifact.RecordingNativeLimit)
		if len(result.Plan.Actions) == 1 && result.Plan.Actions[0].Kind == "logs" {
			maximum = artifact.LogNativeLimit
		}
		limit = min(limit, maximum)
	}
	if approval {
		// ADR-249: an individual approval precedes any observation.
		view := &recorderApprovalView{}
		for _, r := range result.Plan.Approval.Reasons {
			// Codes only, once each: the blocker message is bounded and an
			// ADR-276 group repeats a code per action; the review lists actions.
			if !slices.Contains(view.reasons, r.Code) {
				view.reasons = append(view.reasons, r.Code)
			}
		}
		blockers = append([]OperationBlocker{approvalRequiredBlocker(view)}, blockers...)
		if l := result.Plan.Approval.ObservationLimits; l != nil {
			reads := "A raw byte comparison may test payload bytes"
			if slices.Contains(view.reasons, planning.ReasonHTTPHeaders) {
				reads = "Projecting HTTP headers reads payload bytes" // ADR-282
			}
			if slices.Contains(view.reasons, planning.ReasonSyscallArguments) {
				warnings = append(warnings, "Syscall argument tracing permits bounded user-memory reads; disabling buffers does not disable path reads for selected path syscalls.")
				reads = "Syscall argument tracing"
			}
			warnings = append(warnings, fmt.Sprintf("%s: the approval binds observation limits of %d s per session, %d bytes in total, %d bytes per second and %d concurrent session.", reads, l.MaxSessionSeconds, l.MaxObservedBytes, l.MaxBytesPerSecond, l.MaxConcurrentSessions))
			if l.MaxObservedEvents > 0 {
				warnings = append(warnings, fmt.Sprintf("The same approval also caps eligible entry and exit probes at %d events in total. Failed reads and later-filtered observations consume credit; restarting does not refill it.", l.MaxObservedEvents))
			}
		}
	}
	if !s.config.CollectionEnabled {
		blockers = append(blockers, collectionBlockers(false)...)
	}
	return RecorderPreviewData{ResultAccessActions: recorderResultAccessActions(result.Plan), PreviewID: p.ID, ExpiresAt: p.Deadline, ExecutionDigest: hash(p.ScopeDigest), PodCount: 1, MaxBytes: limit, CaptureEnabled: len(blockers) == 0, ApprovalRequired: approval, Blockers: blockers,
		Warnings: warnings, NavigationURI: s.config.PublicOrigin + "/captures/new", Composition: provenance, Lifecycle: lifecycle, Assessment: RecorderAssessment(result.Assessment), Target: target,
		SelectedPods: []SelectedPod{{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Name: p.Target.PodName, UID: p.Target.PodUID, Workload: SelectedWorkload{Kind: p.Target.Workload.Kind, Name: p.Target.Workload.Name, UID: p.Target.Workload.UID}}}}, result.ValidUntil, nil
}

// This is a display of actual compiled raw output actions, never authority.
// Metadata packet inspection stays ordinary access and needs no result grant.
func recorderResultAccessActions(plan planning.RecorderPlan) []RecorderResultAccessAction {
	if plan.Approval == nil {
		return nil
	}
	var out []RecorderResultAccessAction
	for _, a := range plan.Actions {
		if a.Kind != "profile" && a.Kind != "logs" && a.PacketProfile != "rawPackets" && a.SyscallMode != "arguments" {
			continue
		}
		ops := []string{"download_artifact"}
		if a.Kind == "logs" {
			ops = append(ops, "get_logs")
		}
		if a.Kind == "packetCapture" && a.PacketProfile == "rawPackets" {
			ops = append(ops, "pcap_query")
		}
		if a.Kind == "syscallTrace" && a.SyscallMode == "arguments" {
			ops = append(ops, "syscall_query")
		}
		out = append(out, RecorderResultAccessAction{ActionID: a.ID, Operations: ops})
	}
	return out
}
