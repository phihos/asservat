package planning

import (
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

type processParameters struct {
	Include []string `json:"include"`
}

func normalizeProcesses(path string, a *expandedAction) error {
	if a.action.ExecutionMode == "" {
		a.action.ExecutionMode = "onTrigger"
	}
	if a.action.ExecutionMode != "onTrigger" || a.action.Impact != "observe" || len(a.action.DependsOn) != 0 {
		return refuse(value.CompositionInvalid, path, "process metadata is a finite ordinary observation without dependencies")
	}
	if len(a.processes.Include) != 4 {
		return refuse(value.CompositionRecorderUnavailable, path+".parameters.include", "this version uses the fixed identity, status, threads and cgroups metadata projection")
	}
	slices.Sort(a.processes.Include)
	for n, v := range a.processes.Include {
		if !slices.Contains([]string{"identity", "status", "threads", "cgroups"}, v) || n > 0 && a.processes.Include[n-1] == v {
			return refuse(value.CompositionRecorderUnavailable, path+".parameters.include", "this release does not collect maps, limits, FD targets, arguments or user memory")
		}
	}
	if !slices.Contains(a.processes.Include, "identity") || !slices.Contains(a.processes.Include, "cgroups") {
		return refuse(value.CompositionInvalid, path+".parameters.include", "identity and cgroups are required to prevent PID substitution")
	}
	d, ok := durationValue(a.action.Limits.Timeout, false)
	if !ok || d > 5*time.Second || d%time.Millisecond != 0 || a.action.Limits.MaxBytes < 1 || a.action.Limits.MaxBytes > artifact.ProcessNativeLimit {
		return refuse(value.CompositionInvalid, path+".limits", "process discovery is bounded by 2 MiB native metadata and a five-second action")
	}
	return nil
}

func processesRecorderInput(in value.ContextInput) value.RecorderInput {
	p := in.Processes
	return value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: p.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: p.RequireApproval}
}

func AcceptableProcesses(p value.RecorderPlan) RecorderAcceptance {
	if len(p.Actions) != 1 || p.Actions[0].Kind != "processSnapshot" || p.Actions[0].ExecutionMode != "onTrigger" {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "this release accepts one finite whole-Pod process inventory"}
	}
	return RecorderAcceptance{}
}

func compileProcessesContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	if !in.Capability.Valid(now) || in.Target.ExecutionClass != artifact.ContextAPIExecution || in.Capability.ExecutionClass != artifact.ContextAPIExecution || in.Retention.EvidenceType != "processSnapshot" {
		return value.ContextPlan{}, value.ErrInvalid
	}
	p, e := CompileRecorder(processesRecorderInput(in), nil, now)
	if e != nil || !AcceptableProcesses(p).Acceptable() {
		return value.ContextPlan{}, value.ErrInvalid
	}
	in.Processes = in.Processes.Clone()
	in.Retention.Policies = append(in.Retention.Policies[:0:0], in.Retention.Policies...)
	return value.ContextPlan{Input: in, CanonicalScope: p.CanonicalScope, ScopeDigest: p.ScopeDigest, RecipeDigest: p.RecipeDigest, ValidUntil: identity.Earlier(p.ValidUntil, in.Capability.FreshUntil), CompiledAt: now}, nil
}

func ProcessesPlanForContext(p value.ContextPlan) (value.RecorderPlan, error) {
	if p.Input.Processes == nil {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	r, e := CompileRecorder(processesRecorderInput(p.Input), nil, p.CompiledAt)
	if e != nil || r.ScopeDigest != p.ScopeDigest || !AcceptableProcesses(r).Acceptable() {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	return r, nil
}

func ProcessesForContext(p value.ContextPlan) (artifact.ProcessCapture, string, error) {
	r, e := ProcessesPlanForContext(p)
	if e != nil {
		return artifact.ProcessCapture{}, "", e
	}
	a := r.Actions[0]
	d, ok := durationValue(a.Timeout, false)
	b, e := json.Marshal(p.Input.Processes)
	if e != nil || !ok {
		return artifact.ProcessCapture{}, "", value.ErrInvalid
	}
	out := artifact.ProcessCapture{ActionID: a.ID, Mode: artifact.ProcessAll, MaxNativeBytes: a.MaxBytes, TimeoutMillis: d.Milliseconds(), Composition: b}
	if !out.Valid() {
		return artifact.ProcessCapture{}, "", value.ErrInvalid
	}
	return out, a.ID, nil
}

func ProcessesContextFor(p *artifact.ProcessCapture) (*value.ProcessesContext, error) {
	var out value.ProcessesContext
	if !p.Valid() || strict(p.Composition, &out) != nil || !out.Composition.Valid() {
		return nil, value.ErrInvalid
	}
	for _, c := range out.Composition.Components {
		if c.Profile.Catalog != "builtin" {
			return &out, nil
		}
	}
	a, _, e := expand(out.Composition, nil, nil)
	if e != nil || len(a) != 1 || a[0].processes == nil {
		return nil, value.ErrInvalid
	}
	action, summary, _, e := normalizedRecorderAction(a[0], a[0].componentID)
	d, ok := durationValue(summary.Timeout, false)
	if e != nil || !ok || d.Milliseconds() != p.TimeoutMillis || action.ID != p.ActionID || action.Limits.MaxBytes != p.MaxNativeBytes || p.Mode != artifact.ProcessAll {
		return nil, value.ErrInvalid
	}
	return &out, nil
}

func ProcessesContextFromScope(c value.ProfileComposition, raw []byte) (*value.ProcessesContext, error) {
	var scope recorderScope
	if !c.Valid() || strict(raw, &scope) != nil || len(scope.Filters) != 0 || len(scope.ProfileEndpoints) != 0 || len(scope.ArgumentPrograms) != 0 {
		return nil, value.ErrInvalid
	}
	a, _, e := expand(c, nil, nil)
	if e != nil || len(a) != 1 || a[0].processes == nil {
		return nil, value.ErrInvalid
	}
	out := &value.ProcessesContext{Composition: *c.Clone()}
	if scope.Approval != nil {
		for _, r := range scope.Approval.Reasons {
			if r.Code == value.ReasonRecordingApproval {
				out.RequireApproval = true
			}
		}
	}
	return out, nil
}
