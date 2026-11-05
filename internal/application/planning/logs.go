package planning

import (
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

type logsParameters struct {
	Before string `json:"before"`
	After  string `json:"after"`
	Stream string `json:"stream"`
}

func normalizeLogs(path string, a *expandedAction) error {
	p := a.logs
	if a.action.ExecutionMode == "" {
		a.action.ExecutionMode = "onTrigger"
	}
	if a.action.ExecutionMode != "onTrigger" || len(a.action.DependsOn) != 0 || a.action.Impact != "sensitiveRead" && a.action.Impact != "observe" {
		return refuse(value.CompositionInvalid, path, "logs is a finite observe or sensitiveRead action without dependencies or a container selector")
	}
	before, b := durationValue(p.Before, true)
	after, d := durationValue(p.After, true)
	if !b || !d || before > 24*time.Hour || after > time.Minute || before+after == 0 || before%time.Millisecond != 0 || after%time.Millisecond != 0 {
		return refuse(value.CompositionInvalid, path+".parameters", "logs needs a historical window up to 24h and an after interval up to 60s, with at least one positive")
	}
	if p.Stream != "both" {
		return refuse(value.CompositionRecorderUnavailable, path+".parameters.stream", "this release captures combined streams; exact stdout or stderr needs a qualified Kubernetes split-stream capability")
	}
	timeout, ok := durationValue(a.action.Limits.Timeout, false)
	if !ok || timeout > 5*time.Minute || timeout <= after || timeout%time.Millisecond != 0 {
		return refuse(value.CompositionInvalid, path+".limits.timeout", "the original action timeout must leave time after the requested interval for finite collection, up to 5m")
	}
	if a.action.Limits.MaxBytes < 1 || a.action.Limits.MaxBytes > artifact.LogNativeLimit {
		return refuse(value.CompositionInvalid, path+".limits.maxBytes", "logs native bytes, including JSON/base64 and provenance, must fit the action cap up to 64 MiB")
	}
	if a.action.Impact == "sensitiveRead" {
		a.sensitive = append(a.sensitive, value.ReasonLogs)
	}
	return nil
}

func logsRecorderInput(in value.ContextInput) value.RecorderInput {
	l := in.Logs
	return value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: l.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: l.RequireApproval}
}

func AcceptableLogs(p value.RecorderPlan) RecorderAcceptance {
	if len(p.Actions) != 1 || p.Actions[0].Kind != "logs" || p.Actions[0].ExecutionMode != "onTrigger" || p.Actions[0].LogStream != "both" || p.Approval != nil && (p.Approval.DataClass != "raw" || p.Approval.ObservationLimits != nil) {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "this release acquires one finite whole-pod logs action per capture"}
	}
	return RecorderAcceptance{}
}

func compileLogsContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	if !in.Capability.Valid(now) || in.Target.ExecutionClass != in.Capability.ExecutionClass || in.Target.ExecutionClass != artifact.ContextAPIExecution || in.Retention.EvidenceType != "logs" || in.CaseID != "" && !authorization.UUID(in.CaseID) || !in.Logs.TriggeredAt.IsZero() && in.Logs.TriggeredAt.After(now) {
		return value.ContextPlan{}, value.ErrInvalid
	}
	p, err := CompileRecorder(logsRecorderInput(in), nil, now)
	if err != nil || !AcceptableLogs(p).Acceptable() {
		return value.ContextPlan{}, value.ErrInvalid
	}
	in.Logs = in.Logs.Clone()
	in.Retention.Policies = append(in.Retention.Policies[:0:0], in.Retention.Policies...)
	return value.ContextPlan{Input: in, CanonicalScope: p.CanonicalScope, ScopeDigest: p.ScopeDigest, RecipeDigest: p.RecipeDigest, ValidUntil: identity.Earlier(p.ValidUntil, in.Capability.FreshUntil), CompiledAt: now}, nil
}

func LogsPlanForContext(p value.ContextPlan) (value.RecorderPlan, error) {
	if p.Input.Logs == nil {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	r, err := CompileRecorder(logsRecorderInput(p.Input), nil, p.CompiledAt)
	if err != nil || r.ScopeDigest != p.ScopeDigest || !AcceptableLogs(r).Acceptable() {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	return r, nil
}

func LogsForContext(p value.ContextPlan) (artifact.LogCapture, string, error) {
	plan, err := LogsPlanForContext(p)
	if err != nil {
		return artifact.LogCapture{}, "", err
	}
	a := plan.Actions[0]
	before, b := durationValue(a.Before, true)
	after, d := durationValue(a.After, true)
	timeout, validTimeout := durationValue(a.Timeout, false)
	if !b || !d || !validTimeout {
		return artifact.LogCapture{}, "", value.ErrInvalid
	}
	composition, err := json.Marshal(p.Input.Logs)
	if err != nil {
		return artifact.LogCapture{}, "", err
	}
	l := artifact.LogCapture{ActionID: a.ID, BeforeMillis: before.Milliseconds(), AfterMillis: after.Milliseconds(), Streams: "combined", MaxNativeBytes: a.MaxBytes, TimeoutMillis: timeout.Milliseconds(), Composition: composition}
	if !l.Valid() {
		return artifact.LogCapture{}, "", value.ErrInvalid
	}
	return l, a.ID, nil
}

func LogsContextFor(p *artifact.LogCapture) (*value.LogsContext, error) {
	var out value.LogsContext
	if !p.Valid() || len(p.Composition) == 0 || strict(p.Composition, &out) != nil || !out.Composition.Valid() {
		return nil, value.ErrInvalid
	}
	// Resolved catalog documents are deliberately never persisted. Like the
	// profile restoration path, this restores authored inputs only; the runner
	// must read current versions and recompile/compare the accepted scope.
	for _, component := range out.Composition.Components {
		if component.Profile.Catalog != "builtin" {
			return &out, nil
		}
	}
	actions, _, err := expand(out.Composition, nil, nil)
	if err != nil || len(actions) != 1 || actions[0].logs == nil {
		return nil, value.ErrInvalid
	}
	a, summary, _, err := normalizedRecorderAction(actions[0], actions[0].componentID)
	before, b := durationValue(summary.Before, true)
	after, d := durationValue(summary.After, true)
	timeout, validTimeout := durationValue(summary.Timeout, false)
	if err != nil || !b || !d || !validTimeout || timeout.Milliseconds() != p.TimeoutMillis || a.ID != p.ActionID || before.Milliseconds() != p.BeforeMillis || after.Milliseconds() != p.AfterMillis || a.Limits.MaxBytes != p.MaxNativeBytes || summary.LogStream != "both" {
		return nil, value.ErrInvalid
	}
	return &out, nil
}

func LogsContextFromScope(composition value.ProfileComposition, raw []byte) (*value.LogsContext, error) {
	var scope recorderScope
	if !composition.Valid() || strict(raw, &scope) != nil || len(scope.Filters) != 0 || len(scope.ProfileEndpoints) != 0 || len(scope.ArgumentPrograms) != 0 {
		return nil, value.ErrInvalid
	}
	actions, _, err := expand(composition, nil, nil)
	if err != nil || len(actions) != 1 || actions[0].logs == nil {
		return nil, value.ErrInvalid
	}
	out := &value.LogsContext{Composition: *composition.Clone()}
	if scope.Approval != nil {
		for _, reason := range scope.Approval.Reasons {
			out.RequireApproval = out.RequireApproval || reason.Code == value.ReasonRecordingApproval
		}
	}
	return out, nil
}
