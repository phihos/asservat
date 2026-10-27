package planning

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

// ADR-248: the first accepted recorder plan is a manual networkHeaders packet
// capture of one Pod, recorded by the Pod's node collector through Inspektor
// Gadget's tcpdump gadget. Every other recorder plan keeps the ADR-243
// RecorderUnavailable refusal.

// RecorderAcceptance is why a compiled recorder plan cannot be accepted, with
// the authored field path; empty Code means acceptable.
type RecorderAcceptance struct {
	Code, Path, Reason string
}

func (a RecorderAcceptance) Acceptable() bool { return a.Code == "" }

// AcceptableRecorder checks that plan is a manual networkHeaders packet
// capture this release can run: exactly one packet action, networkHeaders,
// a finite manual session (ongoing manualSession or onTrigger with before 0s)
// of 1 s to 5 min. The interim output cap is 8 MiB per capture: the recording
// stops retaining at the cap; an authored output edit above it is refused.
func AcceptableRecorder(plan value.RecorderPlan) RecorderAcceptance {
	if len(plan.Actions) != 1 {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "only a single packet capture action can be recorded in this release"}
	}
	a := plan.Actions[0]
	if a.Kind != "packetCapture" || a.PacketProfile != "networkHeaders" {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "only network-header packet captures can be recorded in this release"}
	}
	if plan.Approval != nil && plan.Approval.ObservationLimits != nil {
		// ADR-249 REQ-AUT-006: the node recorder does not charge observation
		// spend, so a raw byte predicate cannot be recorded yet.
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "a raw byte comparison needs observation limits that this release's recorder does not enforce"}
	}
	after, ok := durationValue(a.After, true)
	if !ok || after < time.Second || after > 5*time.Minute {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition.components[0] action " + a.LocalID + ".parameters.after", "a manual capture records between 1 second and 5 minutes after it starts"}
	}
	for _, c := range plan.Input.Composition.Components {
		for i, e := range c.Edits {
			if e.Field == "actionMaxBytes" && e.Number > artifact.RecordingNativeLimit {
				return RecorderAcceptance{value.CompositionInvalid, "profile_composition.components[0].overrides[" + strconv.Itoa(i) + "].value", "a capture can save at most 8 MiB in this release; lower the output limit"}
			}
		}
	}
	return RecorderAcceptance{}
}

// RecordingFor derives the node recording of an acceptable plan: the frozen
// filter program from the plan's canonical scope, the recording duration
// (after) and the output cap (the action limit, at most 8 MiB).
func RecordingFor(plan value.RecorderPlan) (artifact.Recording, string, error) {
	if !AcceptableRecorder(plan).Acceptable() {
		return artifact.Recording{}, "", value.ErrInvalid
	}
	a := plan.Actions[0]
	after, _ := durationValue(a.After, true)
	composition, err := json.Marshal(plan.Input.Composition)
	if err != nil {
		return artifact.Recording{}, "", value.ErrInvalid
	}
	r := artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: composition, DurationMillis: after.Milliseconds(),
		MaxBytes: min(a.MaxBytes, artifact.RecordingNativeLimit), Snaplen: artifact.RecordingSnaplen, RequireApproval: plan.Input.RequireApproval}
	var scope recorderScope
	if json.Unmarshal(plan.CanonicalScope, &scope) != nil || len(scope.Filters) > 1 {
		return artifact.Recording{}, "", value.ErrInvalid
	}
	for _, f := range scope.Filters {
		if f.ActionID != a.ID || f.Expression != a.Filter {
			return artifact.Recording{}, "", value.ErrInvalid
		}
		program := make([]artifact.FilterInstruction, len(f.Program))
		for i, ins := range f.Program {
			program[i] = artifact.FilterInstruction{Code: uint16(ins[0]), Jt: uint8(ins[1]), Jf: uint8(ins[2]), K: ins[3]}
		}
		r.Filter = &artifact.RecordingFilter{Expression: f.Expression, Program: program}
	}
	if !r.Valid() || r.MaxBytes < 64<<10 {
		return artifact.Recording{}, "", value.ErrInvalid
	}
	return r, a.ID, nil
}

// RecorderContextFor reconstructs the frozen recorder input of an accepted
// recording, so the hub recompiles exactly the accepted plan without a filter
// compiler.
func RecorderContextFor(r *artifact.Recording) (*value.RecorderContext, error) {
	if !r.Valid() {
		return nil, value.ErrInvalid
	}
	var c value.ProfileComposition
	d := json.NewDecoder(bytes.NewReader(r.Composition))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || !c.Valid() {
		return nil, value.ErrInvalid
	}
	out := &value.RecorderContext{Composition: c, RequireApproval: r.RequireApproval}
	if f := r.Filter; f != nil {
		program := make([]value.BPFInstruction, len(f.Program))
		for i, ins := range f.Program {
			program[i] = value.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		out.Filters = []value.CompiledExpression{{Expression: f.Expression, Filter: value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: program}}}
	}
	return out, nil
}

// frozenFilters answers only the frozen compilations of an accepted plan; any
// other expression is refused as if no compiler were linked.
type frozenFilters []value.CompiledExpression

func (f frozenFilters) CompileFilter(expression string) (value.CompiledFilter, error) {
	for _, c := range f {
		if c.Expression == expression {
			c.Filter.Program = append([]value.BPFInstruction(nil), c.Filter.Program...)
			return c.Filter, nil
		}
	}
	return value.CompiledFilter{}, value.ErrFilterCompilerUnavailable
}

// compileRecorderContext is CompileContext for an accepted recorder plan: the
// scope is the recorder plan's canonical scope (acceptance nodeRecorder); the
// cluster's collection capability must be current, but no pod-status
// projection enters it.
func compileRecorderContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	bad := func() (value.ContextPlan, error) { return value.ContextPlan{}, value.ErrInvalid }
	if !in.Capability.Valid(now) || in.Target.ExecutionClass != in.Capability.ExecutionClass || in.Target.ExecutionClass != artifact.ContextAPIExecution || (in.CaseID != "" && !authorization.UUID(in.CaseID)) {
		return bad()
	}
	evidence, err := RecorderEvidenceType(in.Recorder.Composition)
	if err != nil || in.Retention.EvidenceType != evidence {
		return bad()
	}
	plan, err := CompileRecorder(value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: in.Recorder.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: in.Recorder.RequireApproval}, frozenFilters(in.Recorder.Filters), now)
	if err != nil || !AcceptableRecorder(plan).Acceptable() {
		return bad()
	}
	in.Recorder = in.Recorder.Clone()
	in.Retention.Policies = append(in.Retention.Policies[:0:0], in.Retention.Policies...)
	return value.ContextPlan{Input: in, CanonicalScope: plan.CanonicalScope, ScopeDigest: plan.ScopeDigest, RecipeDigest: plan.RecipeDigest,
		ValidUntil: identity.Earlier(plan.ValidUntil, in.Capability.FreshUntil), CompiledAt: now}, nil
}

// RecorderPlanForContext recompiles the recorder plan of an accepted
// context plan (one compiled through ContextInput.Recorder).
func RecorderPlanForContext(p value.ContextPlan) (value.RecorderPlan, error) {
	in := p.Input
	if in.Recorder == nil {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	plan, err := CompileRecorder(value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: in.Recorder.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: in.Recorder.RequireApproval}, frozenFilters(in.Recorder.Filters), p.CompiledAt)
	if err != nil || plan.ScopeDigest != p.ScopeDigest {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	return plan, nil
}

// RecordingForContext derives the node recording of an accepted context plan.
func RecordingForContext(p value.ContextPlan) (artifact.Recording, string, error) {
	plan, err := RecorderPlanForContext(p)
	if err != nil {
		return artifact.Recording{}, "", err
	}
	return RecordingFor(plan)
}

// RecorderContextFromScope reconstructs the frozen recorder input of a
// reviewed composition preview from its canonical scope.
func RecorderContextFromScope(c value.ProfileComposition, canonicalScope []byte) (*value.RecorderContext, error) {
	if !c.Valid() {
		return nil, value.ErrInvalid
	}
	filters, err := RecorderFiltersOf(value.RecorderPlan{CanonicalScope: canonicalScope})
	if err != nil {
		return nil, err
	}
	var scope recorderScope
	if json.Unmarshal(canonicalScope, &scope) != nil {
		return nil, value.ErrInvalid
	}
	required := false
	if scope.Approval != nil {
		for _, r := range scope.Approval.Reasons {
			required = required || r.Code == value.ReasonRecordingApproval
		}
	}
	return &value.RecorderContext{Composition: *c.Clone(), Filters: filters, RequireApproval: required}, nil
}

// RecorderFiltersOf returns the frozen compilations of a compiled plan, for
// the context input of its acceptance.
func RecorderFiltersOf(plan value.RecorderPlan) ([]value.CompiledExpression, error) {
	var scope recorderScope
	if json.Unmarshal(plan.CanonicalScope, &scope) != nil {
		return nil, value.ErrInvalid
	}
	out := []value.CompiledExpression{}
	for _, f := range scope.Filters {
		program := make([]value.BPFInstruction, len(f.Program))
		for i, ins := range f.Program {
			program[i] = value.BPFInstruction{Code: uint16(ins[0]), Jt: uint8(ins[1]), Jf: uint8(ins[2]), K: ins[3]}
		}
		out = append(out, value.CompiledExpression{Expression: f.Expression, Filter: value.CompiledFilter{LinkType: f.LinkType, Snaplen: f.Snaplen, Program: program}})
	}
	return out, nil
}

// RecorderApprovedAcceptance identifies the explicit ADR-252 timing contract.
// Legacy approved scopes keep their original deadline and cannot be renewed.
func RecorderApprovedAcceptance(scope []byte) bool {
	var s recorderScope
	return strict(scope, &s) == nil && s.Version == value.RecorderPlanVersion && s.Timing == "approvedAcceptance/v1" && s.Deadline == "" && s.Approval != nil
}
