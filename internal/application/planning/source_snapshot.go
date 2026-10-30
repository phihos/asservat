package planning

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// The reviewed selection excludes acceptance/dispatch clocks. Those clocks are
// immutable accepted execution facts, carried separately in the expectation.
type sourceWindowSelection struct {
	RequireApproval                  bool `json:",omitempty"`
	SourceBindingDigest              artifact.Digest
	SourceID, Fence, SnapshotID      string
	SourceStartedAt, SourceHardUntil time.Time
	Before, After                    time.Duration
	MaxBytes                         int64
}

type sourceWindowScope struct {
	Version                                                          string `json:"schemaVersion"`
	CaptureID, CaseID                                                string
	Executor                                                         principal
	Target                                                           authorization.Target
	Namespace, PodName                                               string
	ActionID, PolicyUID, TriggerKind                                 string
	ExecutionDigest, RecipeDigest, CollectorDigest, CapabilityDigest artifact.Digest
	Selection                                                        sourceWindowSelection
	Retention                                                        effectiveRetention
	SourceAudienceDigest                                             artifact.Digest
	OriginalTarget                                                   *targets.SourceSnapshotTarget `json:",omitempty"`
}

func compileSourceSnapshotContext(in value.ContextInput, now time.Time) (value.ContextPlan, error) {
	bad := func() (value.ContextPlan, error) { return value.ContextPlan{}, value.ErrInvalid }
	s := in.Snapshot
	validTarget := in.Target.Valid(now)
	targetUntil := in.Target.FreshUntil
	if observed := in.SnapshotSource; observed != nil {
		validTarget = s != nil && s.SourceTarget != nil && *s.SourceTarget == observed.Original && observed.Valid(now) && in.Target.Request == observed.Original.Request && in.Target.Pin == observed.Original.Pin && in.Target.PodResourceVersion == "" && in.Target.WorkloadResourceVersion == "" && in.Target.ObservedAt.IsZero() && in.Target.FreshUntil.IsZero()
		targetUntil = observed.FreshUntil
	}
	if s == nil || in.Recorder != nil || !s.Request.Valid() || !authorization.UUID(in.CaptureID) || in.CaseID != "" && !authorization.UUID(in.CaseID) || !in.Executor.Valid() || !validTarget || in.Target.ExecutionClass != artifact.ContextAPIExecution || !in.Capability.Valid(now) || in.Capability.ExecutionClass != in.Target.ExecutionClass || !now.Before(in.Deadline) || !s.Request.ProcessingUntil.Equal(in.Deadline) || !identity.Text(s.ActionID, 63) || !identity.Text(s.PolicyUID, 64) || s.ExecutionDigest == (artifact.Digest{}) || s.RecipeDigest == (artifact.Digest{}) || s.TriggerKind != "policy" && s.TriggerKind != "recordingSave" || s.TriggerKind == "recordingSave" && (s.Request.After != 0 || s.Request.Before <= 0) {
		return bad()
	}
	audienceDigest, audienceErr := SourceAudienceDigest(s.SourceAudience)
	if audienceErr != nil || audienceDigest != s.SourceAudienceDigest {
		return bad()
	}
	r := in.Retention
	if r.Target != in.Target.Target() || !r.PolicyRevision.Valid() || !now.Before(r.ValidUntil) || !r.Deadlines.Valid() || !now.Before(r.ExpiresAt) || !r.AnchorAt.Equal(artifact.SourceSnapshotAnchor(s.Request)) || r.PrivacyClass != "potentialPersonalData" || r.EvidenceType != "packetCapture" || !identity.Text(r.PurposeRef, 128) || len(r.Policies) < 1 || len(r.Policies) > 64 || r.RequestedSeconds < 1 || r.MaximumSeconds < 1 || r.DeletionBudgetSeconds < 1 || r.DeletionBudgetSeconds >= r.MaximumSeconds {
		return bad()
	}
	if p := r.Proof; p != (artifact.RetentionProof{}) && (!p.Valid(now) || !p.Matches(p.RootID, r.Target.ClusterID, r.Target.NamespaceUID, r.Target.WorkloadUID, r.Target.PodUID) || p.Policy != r.PolicyRevision || r.ValidUntil.After(p.ValidUntil)) {
		return bad()
	}
	expiry := r.AnchorAt.Add(time.Duration(min(r.RequestedSeconds, r.MaximumSeconds-r.DeletionBudgetSeconds)) * time.Second)
	if !r.ExpiresAt.Equal(expiry) || !r.DeleteBy.Equal(expiry.Add(time.Duration(r.DeletionBudgetSeconds)*time.Second)) {
		return bad()
	}
	refs := slices.Clone(r.Policies)
	slices.SortFunc(refs, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	policies := make([]policyRef, 0, len(refs))
	for n, p := range refs {
		if !identity.Text(p.UID, 64) || p.Generation < 1 || p.Digest == (artifact.Digest{}) || n > 0 && refs[n-1].UID == p.UID {
			return bad()
		}
		policies = append(policies, policyRef{p.UID, p.Generation, hexDigest(p.Digest)})
	}
	q := s.Request
	version := "source-window/v1"
	scope := sourceWindowScope{OriginalTarget: s.SourceTarget, SourceAudienceDigest: s.SourceAudienceDigest, Version: version, CaptureID: in.CaptureID, CaseID: in.CaseID, Executor: principal{in.Executor.Issuer, in.Executor.Subject, in.Executor.ClientID, string(in.Executor.Kind)}, Target: in.Target.Target(), Namespace: in.Target.Request.Namespace.Name, PodName: in.Target.Request.PodName, ActionID: s.ActionID, PolicyUID: s.PolicyUID, TriggerKind: s.TriggerKind, ExecutionDigest: s.ExecutionDigest, RecipeDigest: s.RecipeDigest, CollectorDigest: in.Capability.CollectorImageDigest, CapabilityDigest: artifact.Digest(in.Capability.Revision.Digest), Selection: sourceWindowSelection{q.RequireApproval, q.SourceBindingDigest, q.SourceID, q.Fence, q.SnapshotID, q.SourceStartedAt.UTC(), q.SourceHardUntil.UTC(), q.Before, q.After, q.MaxBytes}, Retention: effectiveRetention{s.ActionID, r.PurposeRef, r.PrivacyClass, r.EvidenceType, r.RequestedSeconds, r.MaximumSeconds, r.DeletionBudgetSeconds, policies}}
	raw, err := json.Marshal(scope)
	if err != nil {
		return bad()
	}
	raw, digest, err := canonical(raw)
	if err != nil {
		return bad()
	}
	until := identity.Earlier(in.Deadline, identity.Earlier(targetUntil, identity.Earlier(in.Capability.FreshUntil, r.ValidUntil)))
	in.Snapshot = in.Snapshot.Clone()
	if in.SnapshotSource != nil {
		observed := *in.SnapshotSource
		in.SnapshotSource = &observed
	}
	in.Retention.Policies = slices.Clone(in.Retention.Policies)
	return value.ContextPlan{Input: in, CanonicalScope: raw, ScopeDigest: digest, RecipeDigest: s.RecipeDigest, ValidUntil: until, CompiledAt: now}, nil
}

func readSourceWindowScopeIdentity(raw []byte, want artifact.Digest) (ContextScopeIdentity, error) {
	var s sourceWindowScope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	encoded, digest, err := canonical(encoded)
	if err != nil || digest != want || !bytes.Equal(encoded, raw) || s.Version != "source-window/v1" && s.Version != "recording-save/v1" || !sourceScopePrincipal(s.Executor).Valid() || !s.Target.Valid() || !authorization.UUID(s.CaptureID) {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	return ContextScopeIdentity{Actor: sourceScopePrincipal(s.Executor), Target: s.Target, CaptureID: s.CaptureID, ExecutionClass: artifact.ContextAPIExecution, ApprovedAcceptance: true}, nil
}

// SourceSnapshotLifecycle is independently derived from admitted request facts;
// no writer report can choose its identity or claim complete observation.
func SourceSnapshotLifecycle(s *value.SourceSnapshotContext) (*artifact.OngoingLifecycle, error) {
	if s == nil || !s.Request.Valid() {
		return nil, value.ErrInvalid
	}
	l := &artifact.OngoingLifecycle{TriggerKind: s.TriggerKind, SourceSessionID: s.Request.SourceID, SourceStartedAt: s.Request.SourceStartedAt, SnapshotID: s.Request.SnapshotID, RequestedBefore: s.Request.Before, After: s.Request.After, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}}
	if s.TriggerKind == "recordingSave" {
		l.Origin = &artifact.RecordingSaveOrigin{PolicyUID: s.PolicyUID, PolicyExecutionDigest: s.ExecutionDigest}
	}
	if l.Validate(s.Request.T0) != nil {
		return nil, value.ErrInvalid
	}
	return l, nil
}

func sourceScopePrincipal(p principal) identity.Principal {
	return identity.Principal{Issuer: p.Issuer, Subject: p.Subject, ClientID: p.ClientID, Kind: identity.Kind(p.Kind)}
}
