package capture

import (
	"context"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type RecordingCandidate struct {
	PolicyName string
	Source     PolicySourceState
}
type RecordingCandidateQuery struct{ PolicyUID, AfterSourceID string }
type RecordingCandidatePage struct {
	Rows          []RecordingCandidate
	AfterSourceID string
	More          bool
}
type RecordingCandidates interface {
	// One SQL scan contains at most100 candidates, ordered by immutable source ID.
	// Policy filtering precedes the scan limit; cursors never convey authority.
	RecordingCandidates(context.Context, authorization.WorkloadTarget, RecordingCandidateQuery) (RecordingCandidatePage, error)
	// Exact bounded lookup also resolves selected handles from later batches.
	RecordingSources(context.Context, authorization.WorkloadTarget, []string) ([]RecordingCandidate, error)
}
type RecordingSelectionStore interface {
	CreateRecordingSelection(context.Context, value.RecordingSelectionSet) error
	ReadRecordingSelection(context.Context, identity.Principal, string) (value.RecordingSelectionSet, error)
}
type RecordingPolicy struct {
	Policy   value.RestartPolicy
	Accepted authorization.AcceptedPolicySnapshot
}
type RecordingPolicies interface {
	RecordingPolicy(context.Context, string, string) (RecordingPolicy, error)
}

// CurrentRecordingPolicies reuses the normal private policy compiler and
// protected acceptance. A stored source cannot preserve a disabled capability.
type CurrentRecordingPolicies struct {
	Documents       PolicyDocuments
	Accepted        authapp.AcceptedPolicyReader
	CompileRecorder PolicyRecorderCompiler
	RecipeName      string
	RecipeDigest    artifact.Digest
	Now             func() time.Time
}

func (s CurrentRecordingPolicies) RecordingPolicy(ctx context.Context, name, uid string) (RecordingPolicy, error) {
	var zero RecordingPolicy
	if s.Documents == nil || s.Accepted == nil || s.CompileRecorder == nil || s.Now == nil {
		return zero, value.ErrUnavailable
	}
	source, raw, err := s.Documents.ReadPolicy(ctx, name, uid)
	if err != nil {
		return zero, err
	}
	accepted, err := s.Accepted.AcceptedPolicyAuthority(ctx, uid)
	if err != nil {
		return zero, err
	}
	p, err := CompilePolicyWithRecorders(raw, s.RecipeName, s.RecipeDigest, s.CompileRecorder)
	a := accepted.Authority
	if err != nil || !source.Valid(s.Now()) || source.Suspended || source.Deleted || !a.Valid(s.Now()) || !s.Now().Before(accepted.SourceUntil) || !p.RecordingSaves || p.Recorder == nil || p.Recorder.Action.ExecutionMode != "ongoing" || RecorderPolicyScopeDigest(source.Revision.UID, accepted.IntentVersion, source.CollectionDigest, p, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits) != a.ScopeDigest {
		return zero, value.ErrDenied
	}
	return RecordingPolicy{Policy: p, Accepted: accepted}, nil
}

// RecordingRow is metadata only. Unknown observation/history stays explicit;
// original source SQL times never become evidence of continuous ring coverage.
type RecordingRow struct {
	IncidentPodCap                                     int
	Handle, PolicyUID, PodUID, PodName, ActionID, Kind string
	State, History                                     string
	MaximumBefore                                      time.Duration
	Blocker                                            string
}
type RecordingPage struct {
	ValidUntil time.Time // Original current observation bound, not handle expiry.
	Rows       []RecordingRow
	Cursor     string
	ExpiresAt  time.Time
}
type RecordingInventory struct {
	RootID      string
	Permissions authapp.WorkloadProjectionReader
	Eligibility ContextEligibilityReader
	Candidates  RecordingCandidates
	Policies    RecordingPolicies
	Selections  RecordingSelectionStore
	Accepted    authapp.AcceptedPolicyReader
	Now         func() time.Time
	NewID       func() string
}

func (s RecordingInventory) authorize(ctx context.Context, current identities.CurrentIdentity, target authorization.WorkloadTarget) (identity.Identity, time.Time, error) {
	if ctx == nil || current == nil || s.Permissions == nil || s.Now == nil || !target.Valid() {
		return identity.Identity{}, time.Time{}, value.ErrInvalid
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:capture") {
		return identity.Identity{}, time.Time{}, value.ErrDenied
	}
	p, err := s.Permissions.WorkloadPermissions(ctx, target)
	if err != nil {
		return identity.Identity{}, time.Time{}, err
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy {
		return identity.Identity{}, time.Time{}, value.ErrDenied
	}
	fresh.ValidUntil = identity.Earlier(fresh.ValidUntil, i.ValidUntil)
	r := authorization.WorkloadScopeEligibility(fresh, p, authorization.CollectContext, target, s.Now())
	if !r.Eligible || ctx.Err() != nil {
		return identity.Identity{}, time.Time{}, value.ErrDenied
	}
	return fresh, r.ValidUntil, nil
}

// List performs no source-report RPC, payload read, ring pin or reservation.
// Current exact source status is resolved only for a selected preview. This
// keeps100-row inventory independent of regional per-source round trips.
func (s RecordingInventory) List(ctx context.Context, current identities.CurrentIdentity, target authorization.WorkloadTarget, policyUID, cursor string, limit int) (RecordingPage, error) {
	var zero RecordingPage
	if ctx == nil || s.Candidates == nil || s.Policies == nil || s.Selections == nil || s.Eligibility == nil || s.Accepted == nil || s.NewID == nil || !authorization.UUID(s.RootID) {
		return zero, value.ErrUnavailable
	}
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 || policyUID != "" && !identity.Text(policyUID, 64) {
		return zero, value.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	i, until, err := s.authorize(call, current, target)
	if err != nil {
		return zero, err
	}
	now := s.Now().UTC().Truncate(time.Microsecond)
	offset := 0
	newBatch := true
	set := value.RecordingSelectionSet{ID: s.NewID(), RootID: s.RootID, Actor: i.Principal, Target: target, PolicyUID: policyUID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	query := RecordingCandidateQuery{PolicyUID: policyUID}
	if cursor != "" {
		id, slot, valid := value.ParseRecordingCursor(cursor)
		if !valid {
			return zero, value.ErrInvalid
		}
		previous, e := s.Selections.ReadRecordingSelection(call, i.Principal, id)
		if e != nil {
			return zero, e
		}
		if !previous.Valid() || previous.RootID != s.RootID || previous.Actor != i.Principal || previous.Target != target || previous.PolicyUID != policyUID || now.Before(previous.CreatedAt) || !now.Before(previous.ExpiresAt) {
			return zero, value.ErrDenied
		}
		if slot == value.MaxRecordingSelections {
			if !previous.More {
				return zero, value.ErrInvalid
			}
			set.CreatedAt, set.ExpiresAt = previous.CreatedAt, previous.ExpiresAt
			query.AfterSourceID = previous.AfterSourceID
		} else {
			if slot >= len(previous.References) {
				return zero, value.ErrInvalid
			}
			set, offset, newBatch = previous, slot, false
		}
	}
	var candidates []RecordingCandidate
	if newBatch {
		page, e := s.Candidates.RecordingCandidates(call, target, query)
		if e != nil {
			return zero, e
		}
		if len(page.Rows) > value.MaxRecordingSelections || page.More && (len(page.Rows) == 0 || !authorization.UUID(page.AfterSourceID)) {
			return zero, value.ErrUnavailable
		}
		candidates = page.Rows
		set.More, set.AfterSourceID = page.More, page.AfterSourceID
	} else {
		ids := make([]string, 0, min(limit, len(set.References)-offset))
		for _, ref := range set.References[offset:min(offset+limit, len(set.References))] {
			ids = append(ids, ref.SourceID)
		}
		candidates, err = s.Candidates.RecordingSources(call, target, ids)
		if err != nil {
			return zero, err
		}
		if len(candidates) > len(ids) {
			return zero, value.ErrUnavailable
		}
	}
	policies := map[string]RecordingPolicy{}
	rejected := map[string]bool{}
	rows := make([]RecordingRow, 0, len(candidates))
	for _, candidate := range candidates {
		source := candidate.Source
		b := source.Binding
		if !newBatch {
			found := false
			for _, ref := range set.References[offset:min(offset+limit, len(set.References))] {
				if source.Target != nil && ref == (value.RecordingReference{SourceID: b.SourceID, Fence: b.Fence, PolicyUID: b.PolicyUID, PodUID: b.PodUID, ActionID: b.ActionID, BindingDigest: artifact.Digest(source.Target.BindingDigest), ExecutionDigest: artifact.Digest(b.Scope)}) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if policyUID != "" && b.PolicyUID != policyUID || source.Target == nil || !source.Target.Valid() || source.ClusterID != target.ClusterID || source.NamespaceUID != target.NamespaceUID || source.WorkloadUID != target.WorkloadUID {
			continue
		}
		// The source row remains private until concrete retained-Pod rights pass.
		caller := s.Eligibility.ContextEligibilityCurrent(call, current, source.Target.Target())
		if !caller.Eligible || caller.Principal != i.Principal {
			continue
		}
		until = identity.Earlier(until, caller.ValidUntil)
		p, ok := policies[b.PolicyUID]
		if !ok {
			if rejected[b.PolicyUID] {
				continue
			}
			p, err = s.Policies.RecordingPolicy(call, candidate.PolicyName, b.PolicyUID)
			if err != nil {
				rejected[b.PolicyUID] = true
				continue
			}
			policies[b.PolicyUID] = p
		}
		a := p.Accepted.Authority
		if a.ClusterID != target.ClusterID || a.NamespaceUID != target.NamespaceUID || a.WorkloadUID != target.WorkloadUID || b.Scope != [32]byte(a.ScopeDigest) || b.AudienceDigest == ([32]byte{}) || len(source.Audience) == 0 || p.Policy.Recorder == nil || b.ActionID != p.Policy.Recorder.Action.ID {
			continue
		}
		executor := newPolicyIdentity(call, s.Accepted, a, identity.Earlier(until, p.Accepted.SourceUntil), s.Now)
		policyRights := s.Eligibility.ContextEligibilityCurrent(call, executor, source.Target.Target())
		if !policyRights.Eligible {
			continue
		}
		until = identity.Earlier(until, policyRights.ValidUntil)
		before, e := time.ParseDuration(p.Policy.Recorder.Action.Before)
		if e != nil {
			return zero, value.ErrUnavailable
		}
		row := RecordingRow{IncidentPodCap: recordingSaveIncidentPodCap(p.Policy), PolicyUID: b.PolicyUID, PodUID: b.PodUID, PodName: source.Target.Request.PodName, ActionID: b.ActionID, Kind: p.Policy.Recorder.Action.Kind, State: "Unknown", History: "Unknown", MaximumBefore: before}
		if before <= 0 {
			row.Blocker = "NoHistoryConfigured"
		} else if !s.Now().Before(source.HardUntil) {
			row.Blocker = "SourceExpired"
		}
		if newBatch {
			set.References = append(set.References, value.RecordingReference{SourceID: b.SourceID, Fence: b.Fence, PolicyUID: b.PolicyUID, PodUID: b.PodUID, ActionID: b.ActionID, BindingDigest: artifact.Digest(source.Target.BindingDigest), ExecutionDigest: a.ScopeDigest})
			row.Handle = set.Handle(len(set.References) - 1)
		} else {
			for slot, ref := range set.References {
				if ref.SourceID == b.SourceID {
					row.Handle = set.Handle(slot)
					break
				}
			}
		}

		rows = append(rows, row)
	}
	if _, _, err = s.authorize(call, current, target); err != nil || !s.Now().Before(until) || call.Err() != nil {
		return zero, value.ErrChanged
	}
	if !set.Valid() {
		return zero, value.ErrUnavailable
	}
	if newBatch && (len(set.References) > 0 || set.More) {
		if err = s.Selections.CreateRecordingSelection(call, set.Clone()); err != nil {
			return zero, err
		}
	}
	fresh, _, err := s.authorize(call, current, target)
	if err != nil || fresh.Principal != i.Principal || !s.Now().Before(until) || call.Err() != nil {
		return zero, value.ErrChanged
	}
	// No hidden-source total is returned. Paging is over this authorized set.
	next := set.BatchCursor()
	if offset+limit < len(set.References) {
		next = set.Handle(offset + limit)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return RecordingPage{Rows: rows, Cursor: next, ExpiresAt: set.ExpiresAt, ValidUntil: until}, nil
}
