package planning

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// AcceptableProfile is the finite Go endpoint subset. Samplers and
// multi-action compositions retain their explicit unavailable boundary.
func AcceptableProfile(p value.RecorderPlan) RecorderAcceptance {
	if len(p.Actions) != 1 || len(p.Input.Endpoints) != 1 || p.Actions[0].Kind != "profile" || p.Actions[0].ProfileSource != "httpEndpoint" || p.Actions[0].ProfileRuntime != "go" || p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits != nil || p.Input.Endpoints[0].Credential {
		return RecorderAcceptance{"RecorderUnavailable", "profile_composition", "this release acquires one approved uncredentialed Go endpoint profile per capture"}
	}
	return RecorderAcceptance{}
}

func profileRecorderInput(in value.ContextInput) value.RecorderInput {
	p := in.Profile
	return value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: p.Composition, Retention: in.Retention, Deadline: in.Deadline, NodeRecorder: true, RequireApproval: p.RequireApproval, Endpoints: p.Endpoints}
}

func compileProfileContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	if !in.Capability.Valid(now) || in.Target.ExecutionClass != in.Capability.ExecutionClass || in.Target.ExecutionClass != artifact.ContextAPIExecution || in.Retention.EvidenceType != "profile" || in.CaseID != "" && !authorization.UUID(in.CaseID) {
		return value.ContextPlan{}, value.ErrInvalid
	}
	p, err := CompileRecorder(profileRecorderInput(in), nil, now)
	if err != nil || !AcceptableProfile(p).Acceptable() {
		return value.ContextPlan{}, value.ErrInvalid
	}
	in.Profile = in.Profile.Clone()
	in.Retention.Policies = append(in.Retention.Policies[:0:0], in.Retention.Policies...)
	return value.ContextPlan{Input: in, CanonicalScope: p.CanonicalScope, ScopeDigest: p.ScopeDigest, RecipeDigest: p.RecipeDigest, ValidUntil: identity.Earlier(p.ValidUntil, in.Capability.FreshUntil), CompiledAt: now}, nil
}

func ProfilePlanForContext(p value.ContextPlan) (value.RecorderPlan, error) {
	if p.Input.Profile == nil {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	r, err := CompileRecorder(profileRecorderInput(p.Input), nil, p.CompiledAt)
	if err != nil || r.ScopeDigest != p.ScopeDigest || !AcceptableProfile(r).Acceptable() {
		return value.RecorderPlan{}, value.ErrInvalid
	}
	return r, nil
}

func ProfileForContext(p value.ContextPlan) (artifact.GoProfileAcquisition, string, error) {
	plan, err := ProfilePlanForContext(p)
	if err != nil {
		return artifact.GoProfileAcquisition{}, "", err
	}
	req := p.Input.Profile.Endpoints[0].Request
	timeout, ok := durationValue(plan.Actions[0].Timeout, false)
	if !ok {
		return artifact.GoProfileAcquisition{}, "", value.ErrInvalid
	}
	composition, err := json.Marshal(p.Input.Profile)
	if err != nil {
		return artifact.GoProfileAcquisition{}, "", err
	}
	return artifact.GoProfileAcquisition{SourceRef: req.SourceRef, EndpointDigest: p.Input.Profile.Endpoints[0].EndpointDigest, Type: req.Type, Mode: req.Mode, DurationMillis: req.DurationSeconds * 1000, ForceGC: req.ForceGC, TimeoutMillis: timeout.Milliseconds(), MaxBytes: req.NativeLimit, Composition: composition}, plan.Actions[0].ID, nil
}

// ProfileContextFor restores only the accepted input; callers recompile and
// compare the complete scope before using it for a new operation.
func ProfileContextFor(p *artifact.GoProfileAcquisition) (*value.ProfileContext, error) {
	var out value.ProfileContext
	if !p.Valid() || len(p.Composition) == 0 || len(p.Composition) > 64<<10 || strict(p.Composition, &out) != nil || !out.Composition.Valid() || len(out.Endpoints) != 1 {
		return nil, value.ErrInvalid
	}
	e := out.Endpoints[0]
	r := e.Request
	if !e.Answers(r) || e.ResolvedAt.IsZero() || p.SourceRef != r.SourceRef || p.EndpointDigest != e.EndpointDigest || p.Type != r.Type || p.Mode != r.Mode || p.DurationMillis != r.DurationSeconds*1000 || p.ForceGC != r.ForceGC || p.MaxBytes != r.NativeLimit || p.TimeoutMillis < p.DurationMillis+5000 || p.TimeoutMillis > p.DurationMillis+10000 {
		return nil, value.ErrInvalid
	}
	return &out, nil
}

// ProfileContextFromScope reconstructs the immutable preview observation. It
// never substitutes a fresh endpoint or moves its original observation time.
func ProfileContextFromScope(c value.ProfileComposition, target targets.Request, raw []byte) (*value.ProfileContext, error) {
	var scope recorderScope
	if !c.Valid() || strict(raw, &scope) != nil || len(scope.ProfileEndpoints) != 1 || len(scope.Filters) != 0 {
		return nil, value.ErrInvalid
	}
	actions, _, err := expand(c, nil, nil)
	if err != nil || len(actions) != 1 || actions[0].profile == nil || actions[0].profile.Source.Kind != "httpEndpoint" {
		return nil, value.ErrInvalid
	}
	a, _, _, err := normalizedRecorderAction(actions[0], actions[0].componentID)
	if err != nil {
		return nil, value.ErrInvalid
	}
	record := scope.ProfileEndpoints[0]
	req := endpointRequest(target, actions[0])
	if record.ActionID != a.ID || record.SourceRef != req.SourceRef {
		return nil, value.ErrInvalid
	}
	e := targets.ProfileEndpointResolution{Request: req, SourceKind: record.SourceKind, SourceName: record.SourceName, AddressMode: record.AddressMode, Port: record.Port, DeclaredPortName: record.DeclaredPortName, PathPolicy: record.PathPolicy, TLS: record.TLS, Credential: record.Credential}
	for _, v := range []struct {
		raw string
		dst *artifact.Digest
	}{{record.EndpointDigest, &e.EndpointDigest}, {record.DefinitionDigest, &e.DefinitionDigest}} {
		b, err := hex.DecodeString(v.raw)
		if err != nil || len(b) != len(*v.dst) {
			return nil, value.ErrInvalid
		}
		copy(v.dst[:], b)
	}
	e.ResolvedAt, err = time.Parse(time.RFC3339Nano, record.ResolvedAt)
	if err != nil || !e.Answers(req) {
		return nil, value.ErrInvalid
	}
	out := &value.ProfileContext{Composition: *c.Clone(), Endpoints: []targets.ProfileEndpointResolution{e}}
	if scope.Approval != nil {
		for _, r := range scope.Approval.Reasons {
			out.RequireApproval = out.RequireApproval || r.Code == value.ReasonRecordingApproval
		}
	}
	return out, nil
}
