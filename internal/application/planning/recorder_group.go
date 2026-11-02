package planning

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
)

// RecorderGroupVersion is the parent scope of a manual composition group
// (ADR-276): one review over the children's exact scope digests.
const RecorderGroupVersion = "recorder-group/v1"

type recorderGroupChild struct {
	CaptureID    string `json:"captureID"`
	ActionID     string `json:"actionID"`
	Kind         string `json:"kind"`
	EvidenceType string `json:"evidenceType"`
	ScopeDigest  string `json:"scopeDigest"`
}

type recorderGroupScope struct {
	Version   string         `json:"schemaVersion"`
	CaptureID string         `json:"captureID"`
	Executor  principal      `json:"executor"`
	Target    recorderTarget `json:"target"`
	Source    source         `json:"source"`
	Approval  bool           `json:"approvalRequired"`
	// Timing is the children's shared approved-timing marker; the parent
	// grant carries it like a single recorder's (lock_approved_context_grant).
	Timing   string               `json:"timing,omitempty"`
	Children []recorderGroupChild `json:"children"`
	// Provenance and Lifecycle merge the children's for review display
	// (CompositionProvenance, LifecyclePlanJSON); children bind execution.
	Provenance wireProvenance `json:"profileComposition"`
	Lifecycle  lifecyclePlan  `json:"lifecycle"`
}

// CompileRecorderGroup binds already compiled single-action child plans of
// one Pod into the canonical parent scope. Children must share executor,
// target and the approval requirement; each keeps its own scope and digest.
func CompileRecorderGroup(captureID string, children []value.RecorderPlan) ([]byte, artifact.Digest, error) {
	bad := func() ([]byte, artifact.Digest, error) { return nil, artifact.Digest{}, value.ErrInvalid }
	if len(children) < 2 || len(children) > 16 {
		return bad()
	}
	var out recorderGroupScope
	for i, p := range children {
		var s recorderScope
		if len(p.Actions) != 1 || strict(p.CanonicalScope, &s) != nil || s.Version != value.RecorderPlanVersion {
			return bad()
		}
		if i == 0 {
			out = recorderGroupScope{Version: RecorderGroupVersion, CaptureID: captureID, Executor: s.Executor, Target: s.Target, Source: source{s.Source.ClusterID, s.Source.NamespaceUID, captureID}, Approval: s.Approval != nil, Timing: s.Timing}
		} else if s.Timing != out.Timing || s.Executor != out.Executor || s.Target != out.Target || s.Source.ClusterID != out.Source.ClusterID || s.Source.NamespaceUID != out.Source.NamespaceUID || (s.Approval != nil) != out.Approval {
			return bad()
		}
		if i == 0 {
			out.Provenance.Authored.MaxTotalBytes, out.Provenance.Authored.MaxDuration = s.Provenance.Authored.MaxTotalBytes, s.Provenance.Authored.MaxDuration
			out.Lifecycle = lifecyclePlan{SchemaVersion: s.Lifecycle.SchemaVersion, RequestKind: s.Lifecycle.RequestKind, OngoingPodScope: s.Lifecycle.OngoingPodScope}
		}
		out.Provenance.Authored.Components = append(out.Provenance.Authored.Components, s.Provenance.Authored.Components...)
		out.Provenance.ResolvedProfiles = append(out.Provenance.ResolvedProfiles, s.Provenance.ResolvedProfiles...)
		out.Provenance.ActionMap = append(out.Provenance.ActionMap, s.Provenance.ActionMap...)
		out.Lifecycle.Actions = append(out.Lifecycle.Actions, s.Lifecycle.Actions...)
		a := p.Actions[0]
		out.Children = append(out.Children, recorderGroupChild{CaptureID: s.Source.ResourceUID, ActionID: a.ID, Kind: a.Kind, EvidenceType: a.EvidenceType, ScopeDigest: hexDigest(p.ScopeDigest)})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return bad()
	}
	b, d, err := canonical(b)
	if err != nil || len(b) > 64<<10 {
		return bad()
	}
	return b, d, nil
}

// RecorderGroupScope is the read view of a recorder-group/v1 parent scope.
type RecorderGroupScope struct {
	CaptureID    string
	Executor     identity.Principal
	Target       authorization.Target
	ChildCapture []string
	ChildScope   []artifact.Digest
}

// ReadRecorderGroupScope strictly reads a canonical parent scope whose
// digest is d.
func ReadRecorderGroupScope(scope []byte, d artifact.Digest) (RecorderGroupScope, error) {
	var out RecorderGroupScope
	var s recorderGroupScope
	if c, digest, err := canonical(scope); err != nil || digest != d || !bytes.Equal(c, scope) || strict(scope, &s) != nil || s.Version != RecorderGroupVersion || len(s.Children) < 2 || len(s.Children) > 16 {
		return out, value.ErrInvalid
	}
	out = RecorderGroupScope{CaptureID: s.CaptureID, Executor: identity.Principal{Issuer: s.Executor.Issuer, Subject: s.Executor.Subject, ClientID: s.Executor.ClientID, Kind: identity.Kind(s.Executor.Kind)}, Target: authorization.Target{ClusterID: s.Source.ClusterID, NamespaceUID: s.Source.NamespaceUID, WorkloadUID: s.Target.Workload.UID, PodUID: s.Target.PodUID}}
	for _, c := range s.Children {
		b, err := hex.DecodeString(c.ScopeDigest)
		if err != nil || len(b) != len(artifact.Digest{}) {
			return RecorderGroupScope{}, value.ErrInvalid
		}
		out.ChildCapture = append(out.ChildCapture, c.CaptureID)
		out.ChildScope = append(out.ChildScope, artifact.Digest(b))
	}
	return out, nil
}

// RecorderGroupDisplay merges the children's plans and assessments into the
// one plan and assessment a reviewer sees for the parent (ADR-276). It is
// display and approval input only; each child plan alone is executed.
func RecorderGroupDisplay(scope []byte, digest artifact.Digest, assessmentID string, plans []value.RecorderPlan, assessments []value.RecorderAssessment) (value.RecorderPlan, value.RecorderAssessment, error) {
	if len(plans) < 2 || len(plans) != len(assessments) {
		return value.RecorderPlan{}, value.RecorderAssessment{}, value.ErrInvalid
	}
	plan := value.RecorderPlan{Input: plans[0].Input, CanonicalScope: bytes.Clone(scope), ScopeDigest: digest, CompiledAt: plans[0].CompiledAt, ValidUntil: plans[0].ValidUntil}
	a := assessments[0]
	a.ID, a.PlanDigest, a.Actions, a.CombinedQuantities = assessmentID, digest, nil, nil
	a.Combined.Effects = nil
	for i, p := range plans {
		if (p.Approval == nil) != (plans[0].Approval == nil) || assessments[i].RulesDigest != a.RulesDigest {
			return value.RecorderPlan{}, value.RecorderAssessment{}, value.ErrInvalid
		}
		plan.Actions = append(plan.Actions, p.Actions...)
		plan.Profiles = append(plan.Profiles, p.Profiles...)
		plan.CompiledAt = maxTime(plan.CompiledAt, p.CompiledAt)
		plan.ValidUntil = identity.Earlier(plan.ValidUntil, p.ValidUntil)
		if p.Approval != nil {
			if plan.Approval == nil {
				plan.Approval = &value.RecorderApproval{DataClass: p.Approval.DataClass}
			}
			if p.Approval.DataClass != plan.Approval.DataClass {
				return value.RecorderPlan{}, value.RecorderAssessment{}, value.ErrInvalid
			}
			plan.Approval.Reasons = append(plan.Approval.Reasons, p.Approval.Reasons...)
			if plan.Approval.ObservationLimits == nil {
				plan.Approval.ObservationLimits = p.Approval.ObservationLimits
			}
		}
		c := assessments[i]
		a.Actions = append(a.Actions, c.Actions...)
		a.CombinedQuantities = append(a.CombinedQuantities, c.CombinedQuantities...)
		a.GeneratedAt = maxTime(a.GeneratedAt, c.GeneratedAt)
		a.ValidUntil = identity.Earlier(a.ValidUntil, c.ValidUntil)
		a.Combined.HasUnknowns = a.Combined.HasUnknowns || c.Combined.HasUnknowns
		for _, e := range c.Combined.Effects {
			if !slices.Contains(a.Combined.Effects, e) {
				a.Combined.Effects = append(a.Combined.Effects, e)
			}
		}
	}
	return plan, a, nil
}

// RecorderGroupSummary is RecorderScopeSummary over a group's child scopes:
// the actions and the merged approval one grant review covers.
func RecorderGroupSummary(children [][]byte) ([]value.RecorderAction, *value.RecorderApproval, error) {
	var actions []value.RecorderAction
	var approval *value.RecorderApproval
	for i, scope := range children {
		a, p, err := RecorderScopeSummary(scope)
		if err != nil || i > 0 && (p == nil) != (approval == nil) {
			return nil, nil, value.ErrInvalid
		}
		actions = append(actions, a...)
		if p == nil {
			continue
		}
		if approval == nil {
			approval = &value.RecorderApproval{DataClass: p.DataClass}
		}
		if p.DataClass != approval.DataClass {
			return nil, nil, value.ErrInvalid
		}
		approval.Reasons = append(approval.Reasons, p.Reasons...)
		if approval.ObservationLimits == nil {
			approval.ObservationLimits = p.ObservationLimits
		}
	}
	return actions, approval, nil
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
