package capture

import (
	"context"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type RecordingSavePreviewRequest struct {
	Handles               []string
	Before                time.Duration
	Sharing               *value.ContextSharing
	RepeatedFromCaptureID string
}

// RecordingSaves uses passive inventory handles only to identify original
// sources. Both principals and the exact accepted policy are independently
// checked again; a handle never supplies an executor or an acceptance clock.
type RecordingSaves struct {
	Targets       RecordingTargetResolver
	Inventory     RecordingInventory
	Investigation ContextInvestigation
	History       interface {
		Settings(context.Context, identities.CurrentIdentity, string) (value.CaptureSettings, error)
	}
}

type RecordingTargetResolver interface {
	ResolveWorkloadIdentity(context.Context, targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error)
}

// List resolves only the named workload identity. No Pod selection or live
// Pod proof is required to discover still-authorized stopped source windows.
func (s RecordingSaves) List(ctx context.Context, current identities.CurrentIdentity, target targets.WorkloadRequest, policyUID, cursor string, limit int) (RecordingPage, error) {
	var zero RecordingPage
	if ctx == nil || current == nil || s.Targets == nil || s.Inventory.Now == nil {
		return zero, value.ErrUnavailable
	}
	if !target.Valid() {
		return zero, value.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	i, err := current.ResolveIdentity(call)
	if err != nil || !i.Valid(s.Inventory.Now()) || !slices.Contains(i.Scopes, "evidence:capture") {
		return zero, value.ErrDenied
	}
	resolved, err := s.Targets.ResolveWorkloadIdentity(call, target)
	if err != nil {
		return zero, err
	}
	if !resolved.Valid(s.Inventory.Now()) || resolved.Reference != target {
		return zero, value.ErrChanged
	}
	until := identity.Earlier(i.ValidUntil, resolved.FreshUntil)
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	page, err := s.Inventory.List(bounded, current, resolved.Target(), policyUID, cursor, limit)
	if err != nil {
		return zero, err
	}
	fresh, err := current.ResolveIdentity(bounded)
	if err != nil || !fresh.Valid(s.Inventory.Now()) || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !resolved.Valid(s.Inventory.Now()) || bounded.Err() != nil {
		return zero, value.ErrDenied
	}
	page.ValidUntil = identity.Earlier(page.ValidUntil, identity.Earlier(until, fresh.ValidUntil))
	return page, nil
}

func (s RecordingSaves) Preview(ctx context.Context, current identities.CurrentIdentity, request RecordingSavePreviewRequest) (ContextPreviewResult, error) {
	var zero ContextPreviewResult
	if ctx == nil || current == nil || s.Inventory.Selections == nil || s.Inventory.Candidates == nil || s.Inventory.Policies == nil || s.Inventory.Accepted == nil || s.Inventory.Now == nil {
		return zero, value.ErrUnavailable
	}
	if len(request.Handles) < 1 || len(request.Handles) > 16 || request.Before < 0 || request.Before > artifact.MaxLifecycleWindow || request.Before%time.Millisecond != 0 {
		return zero, value.ErrInvalid
	}
	if request.Sharing != nil && !request.Sharing.Valid() {
		return zero, value.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	i, err := current.ResolveIdentity(call)
	if err != nil || !i.Valid(s.Inventory.Now()) || !slices.Contains(i.Scopes, "evidence:capture") {
		return zero, value.ErrDenied
	}
	id, _, ok := value.ParseRecordingHandle(request.Handles[0])
	if !ok {
		return zero, value.ErrInvalid
	}
	set, err := s.Inventory.Selections.ReadRecordingSelection(call, i.Principal, id)
	if err != nil {
		return zero, err
	}
	if _, _, err = s.Inventory.authorize(call, current, set.Target); err != nil {
		return zero, err
	}
	refs, err := set.Select(i.Principal, request.Handles, s.Inventory.Now())
	if err != nil {
		return zero, err
	}
	// The currently implemented policy compiler accepts one packet action and
	// an incident Pod cap of1. The canonical builder retains the1..16 schema;
	// this route cannot silently discard additional selected sources.
	if len(refs) != 1 {
		return zero, value.ErrCapacity
	}
	candidates, err := s.Inventory.Candidates.RecordingSources(call, set.Target, []string{refs[0].SourceID})
	if err != nil {
		return zero, err
	}
	var chosen *RecordingCandidate
	for n := range candidates {
		candidate := &candidates[n]
		source := candidate.Source
		b := source.Binding
		if source.Target == nil {
			continue
		}
		ref := value.RecordingReference{SourceID: b.SourceID, Fence: b.Fence, PolicyUID: b.PolicyUID, PodUID: b.PodUID, ActionID: b.ActionID, BindingDigest: artifact.Digest(source.Target.BindingDigest), ExecutionDigest: artifact.Digest(b.Scope)}
		if ref == refs[0] {
			if chosen != nil {
				return zero, value.ErrChanged
			}
			chosen = candidate
		}
	}
	if chosen == nil {
		return zero, value.ErrChanged
	}
	policy, err := s.Inventory.Policies.RecordingPolicy(call, chosen.PolicyName, refs[0].PolicyUID)
	if err != nil {
		return zero, err
	}
	if policy.Accepted.Authority.ScopeDigest != refs[0].ExecutionDigest || !policy.Policy.RecordingSaves {
		return zero, value.ErrDenied
	}
	var lineage *value.HistoryLineage
	if request.RepeatedFromCaptureID != "" {
		if s.History == nil {
			return zero, value.ErrSettingsUnavailable
		}
		settings, e := s.History.Settings(call, current, request.RepeatedFromCaptureID)
		if e != nil {
			return zero, e
		}
		if settings.RecordingSave == nil || settings.RecordingSave.PolicyUID != refs[0].PolicyUID || settings.ClusterID != set.Target.ClusterID || settings.NamespaceUID != set.Target.NamespaceUID || settings.WorkloadUID != set.Target.WorkloadUID {
			return zero, value.ErrInvalid
		}
		lineage = &value.HistoryLineage{CaptureID: settings.CaptureID, ExpiresAt: settings.ExpiresAt.UTC().Truncate(time.Microsecond)}
	}
	until := identity.Earlier(i.ValidUntil, policy.Accepted.SourceUntil)
	executor := newPolicyIdentity(call, s.Inventory.Accepted, policy.Accepted.Authority, until, s.Inventory.Now)
	result, err := s.Investigation.previewSourceSnapshot(call, executor, PolicySnapshotSelection{PolicyName: chosen.PolicyName, Policy: policy.Policy, Authority: policy.Accepted.Authority, Source: chosen.Source, Target: chosen.Source.Target.Request, TriggeredAt: s.Inventory.Now().UTC().Truncate(time.Microsecond)}, &manualSnapshotSelection{Current: current, Before: request.Before, Sharing: request.Sharing, RepeatedFrom: lineage})
	if err == nil && result.RecordingSave != nil && len(result.RecordingSave.Selected) == 1 {
		result.RecordingSave.Selected[0].Handle = request.Handles[0]
	}
	return result, err
}

func (s RecordingSaves) Request(ctx context.Context, current identities.CurrentIdentity, preview, key string) (value.Accepted, error) {
	investigation := s.Investigation
	investigation.RecordingPolicies = s.Inventory.Policies
	investigation.PolicyAccepted = s.Inventory.Accepted
	return investigation.Request(ctx, current, preview, key)
}
