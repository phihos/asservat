// Package presentation provides shared browser/MCP wire projections. It never
// resolves authority, fetches evidence or starts collection.
package presentation

import (
	"encoding/hex"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

type Impact struct {
	Level       string   `json:"level"`
	HasUnknowns bool     `json:"hasUnknowns"`
	Effects     []string `json:"effects"`
	Explanation string   `json:"explanation"`
}
type Exposure struct {
	Classification   string   `json:"classification"`
	Basis            string   `json:"basis"`
	RetainedPossible []string `json:"retainedPossible"`
	TransientOnly    []string `json:"transientOnly"`
	UnknownContent   bool     `json:"unknownContent"`
}
type Retention struct {
	AnchorRule            string   `json:"anchorRule"`
	AccessAgeSeconds      int64    `json:"accessAgeSeconds"`
	DeleteAgeSeconds      int64    `json:"deleteAgeSeconds"`
	MaximumAgeSeconds     int64    `json:"maximumAgeSeconds"`
	DeletionBudgetSeconds int64    `json:"deletionBudgetSeconds"`
	PolicyDigests         []string `json:"policyDigests"`
	AutomaticDeletion     bool     `json:"automaticDeletion"`
	ManagedCopiesOnly     bool     `json:"managedCopiesOnly"`
	PreservationException string   `json:"preservationException"`
}
type Quantity struct {
	Dimension string `json:"dimension"`
	Phase     string `json:"phase"`
	Scope     string `json:"scope"`
	Basis     string `json:"basis"`
	Lower     int64  `json:"lower"`
	Upper     int64  `json:"upper"`
	SourceRef string `json:"sourceRef"`
	Coverage  string `json:"coverage"`
}
type AssessmentAction struct {
	RecordingHandle string     `json:"recording_handle,omitempty"`
	ActionID        string     `json:"actionID"`
	ExecutionMode   string     `json:"executionMode"`
	Impact          Impact     `json:"impact"`
	Data            Exposure   `json:"data"`
	Retention       Retention  `json:"retention"`
	Quantities      []Quantity `json:"quantities"`
}
type Interaction struct {
	ActionIDs []string `json:"actionIDs"`
	Kind      string   `json:"kind"`
	Message   string   `json:"message"`
	Blocking  bool     `json:"blocking"`
}
type Alternative struct {
	ActionIDs    []string `json:"actionIDs"`
	Change       string   `json:"change"`
	Benefit      string   `json:"benefit"`
	CoverageLoss string   `json:"coverageLoss"`
}
type AssessmentBasis struct {
	RulesDigest      string `json:"rulesDigest"`
	CapabilityDigest string `json:"capabilityDigest"`
	Metrics          struct {
		State string `json:"state"`
	} `json:"metrics"`
}
type AssessmentScope struct {
	ObservationPods int `json:"observationPods"`
	IncidentPods    int `json:"incidentPods"`
}
type CaptureAssessment struct {
	SchemaVersion      string             `json:"schemaVersion"`
	AssessmentID       string             `json:"assessmentID"`
	PlanDigest         string             `json:"planDigest"`
	GeneratedAt        time.Time          `json:"generatedAt"`
	ValidUntil         time.Time          `json:"validUntil"`
	Basis              AssessmentBasis    `json:"basis"`
	Scope              AssessmentScope    `json:"scope"`
	CombinedImpact     Impact             `json:"combinedImpact"`
	Actions            []AssessmentAction `json:"actions"`
	CombinedQuantities []Quantity         `json:"combinedQuantities"`
	Interactions       []Interaction      `json:"interactions"`
	Alternatives       []Alternative      `json:"alternatives"`
	HandlingCodes      []string           `json:"handlingCodes"`
}
type LifecycleAction struct {
	ActionID      string `json:"actionID"`
	Kind          string `json:"kind"`
	ExecutionMode string `json:"executionMode"`
}
type LifecyclePlan struct {
	SchemaVersion   string            `json:"schemaVersion"`
	RequestKind     string            `json:"requestKind"`
	Actions         []LifecycleAction `json:"actions"`
	OngoingPodScope string            `json:"ongoingPodScope"`
}

func hash(d artifact.Digest) string { return hex.EncodeToString(d[:]) }

// ContextAssessment converts the explanatory service result, after current
// caller eligibility has been established. Its output does not itself authorize
// collection, waive a warning or set an evidence expiry timestamp.
func ContextAssessment(a value.ContextAssessment) CaptureAssessment {
	impact := Impact{a.Impact.Level, a.Impact.HasUnknowns, slices.Clone(a.Impact.Effects), a.Impact.Explanation}
	r := a.Retention
	policies := make([]string, 0, len(r.PolicyDigests))
	for _, d := range r.PolicyDigests {
		policies = append(policies, hash(d))
	}
	limit := Quantity{Dimension: "outputBytes", Phase: "perIncident", Scope: "wholePlan", Basis: "configuredLimit", Lower: 0, Upper: a.OutputLimit, SourceRef: "builtin-pod-status-v1", Coverage: "Native saved status only; excludes the API response, object/encryption overhead and total collector memory."}
	basis := AssessmentBasis{RulesDigest: hash(a.RulesDigest), CapabilityDigest: hash(a.CapabilityDigest)}
	basis.Metrics.State = "unavailable"
	return CaptureAssessment{
		SchemaVersion: "capture-assessment/v1", AssessmentID: a.ID, PlanDigest: hash(a.PlanDigest), GeneratedAt: a.GeneratedAt, ValidUntil: a.ValidUntil,
		Basis: basis, Scope: AssessmentScope{ObservationPods: 0, IncidentPods: 1}, CombinedImpact: impact,
		Actions: []AssessmentAction{{ActionID: "pod-status", ExecutionMode: "onTrigger", Impact: Impact{impact.Level, impact.HasUnknowns, slices.Clone(impact.Effects), impact.Explanation},
			Data:       Exposure{a.Exposure.Classification, a.Exposure.Basis, slices.Clone(a.Exposure.RetainedPossible), slices.Clone(a.Exposure.TransientOnly), a.Exposure.UnknownContent},
			Retention:  Retention{"submissionPreparation", r.AccessAgeSeconds, r.DeleteAgeSeconds, r.MaximumAgeSeconds, r.DeletionBudgetSeconds, policies, true, true, "possible"},
			Quantities: []Quantity{limit}}},
		CombinedQuantities: []Quantity{limit},
		Interactions:       []Interaction{{ActionIDs: []string{"pod-status"}, Kind: "sharedPressure", Message: "Current node, API and upload pressure and other collectors are not measured by this preview.", Blocking: false}},
		Alternatives:       []Alternative{},
		HandlingCodes:      []string{"minimizeCapture", "restrictAccess", "preferApprovedExtracts", "reviewBeforeSharing", "approvedClientsOnly", "externalCopiesNotRecalled"},
	}
}

func ContextLifecycle() LifecyclePlan {
	return LifecyclePlan{SchemaVersion: "action-lifecycle/v1", RequestKind: "DebugCapture", Actions: []LifecycleAction{{"pod-status", "kubernetesSnapshot", "onTrigger"}}, OngoingPodScope: "none"}
}
