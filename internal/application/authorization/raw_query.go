package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// RawQueryReview is presentation of the immutable exact-artifact scope. Its
// display names come from accepted provenance; ReviewDigest binds these bytes.
type RawQueryReview struct {
	CaseID                  string
	Artifacts               []RawQueryReviewArtifact
	Operations              []string
	Reason                  string
	MaxBytes, MaxOperations int64
	NotAfter                time.Time
}
type RawQueryReviewArtifact struct {
	Output                                                     value.VerifiedOutput
	NativeBytes                                                int64
	ExpiresAt                                                  time.Time
	Namespace, WorkloadKind, WorkloadName, PodName, NativeType string
}
type RawQuerySelection struct {
	Artifacts  []value.RawQueryArtifact
	Review     []RawQueryReviewArtifact
	ValidUntil time.Time
}
type RawQuerySelectionReader interface {
	ResolveRawQuery(context.Context, identities.CurrentIdentity, string, []artifact.Digest) (RawQuerySelection, error)
}

// RawQueryGrantStore adds only reads of the existing grant/child/use ledger.
// An existing use always keeps its original parent, even after another approval.
type RawQueryGrantStore interface {
	RawQueryRequest(context.Context, identity.Principal, string) (StoredGrantRequest, error)
	RawQueryCandidates(context.Context, artifact.DownloadScope, value.GrantUse) ([]value.Grant, error)
	GrantUseByID(context.Context, string) (GrantUseRequest, error)
	// CountRegisteredGrantArtifacts counts distinct selected artifacts already
	// registered under the parent across its reviewed clients; at most 64 IDs.
	CountRegisteredGrantArtifacts(context.Context, string, []string) (int, error)
}
type RawPacketQuerySelectionReader interface {
	ResolveRawPacketQuery(context.Context, identities.CurrentIdentity, string, []artifact.Digest) (RawQuerySelection, error)
}

type RawQueryRequestInput struct {
	CaseID          string
	ArtifactDigests []artifact.Digest
	Operations      []string
	Reason          string
	MaxBytes        int64
	Lifetime        time.Duration
	IdempotencyKey  string
}

func normalizeRawQueryRequest(in RawQueryRequestInput) (RawQueryRequestInput, error) {
	in.ArtifactDigests = slices.Clone(in.ArtifactDigests)
	slices.SortFunc(in.ArtifactDigests, func(a, b artifact.Digest) int { return bytes.Compare(a[:], b[:]) })
	in.Operations = slices.Clone(in.Operations)
	slices.Sort(in.Operations)
	if !value.UUID(in.CaseID) || len(in.ArtifactDigests) < 1 || len(in.ArtifactDigests) > value.GrantMaxResultArtifacts || !identity.Text(in.Reason, 512) || !identity.Text(in.IdempotencyKey, 128) || in.MaxBytes < 1 || in.MaxBytes > artifact.MaxNativeBytes || in.Lifetime < time.Second || in.Lifetime > value.GrantMaxLifetime || in.Lifetime%time.Second != 0 {
		return in, value.ErrGrantInvalid
	}
	if !value.ValidResultOperations(in.Operations) {
		return in, ErrRawQueryOperationUnsupported
	}
	for n, d := range in.ArtifactDigests {
		if d == (artifact.Digest{}) || n > 0 && d == in.ArtifactDigests[n-1] {
			return in, value.ErrGrantInvalid
		}
	}
	return in, nil
}

var ErrRawQueryOperationUnsupported = errors.New("raw operation is not implemented")

func rawQueryRequestDigest(in RawQueryRequestInput, p identity.Principal) artifact.Digest {
	// Relative lifetime belongs to the original caller intent. Wall-clock reads
	// and derived retention facts must not turn an uncertain replay into renewal.
	b, _ := json.Marshal(struct {
		Version   string
		Requester identity.Principal
		Input     RawQueryRequestInput
	}{"raw-query-request/v1", p, in})
	return sha256.Sum256(b)
}

func (s GrantService) RequestRaw(ctx context.Context, current identities.CurrentIdentity, in RawQueryRequestInput) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() || s.RawStore == nil || s.RawSelections == nil {
		return zero, false, ErrGrantUnavailable
	}
	in, err := normalizeRawQueryRequest(in)
	if err != nil {
		return zero, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	scopes := []string{"evidence:download"}
	if !slices.Contains(in.Operations, value.GrantDownloadOperation) {
		scopes = []string{"evidence:read", "evidence:raw"}
	}
	i, err := s.human(ctx, current, scopes...)
	if err != nil {
		return zero, false, err
	}
	digest := rawQueryRequestDigest(in, i.Principal)
	prior, err := s.RawStore.RawQueryRequest(ctx, i.Principal, in.IdempotencyKey)
	if err == nil {
		g := prior.Grant
		if prior.RequestDigest != digest || g.Requester != i.Principal || !RawQueryScopeMatches(g) || ReviewDigest(g, g.Review) != g.ReviewDigest {
			return zero, false, ErrGrantConflict
		}
		eligible, e := s.grantEligibility(ctx, i, g, value.DownloadApproved)
		if e != nil || !eligible.Eligible {
			return zero, false, identity.ErrDenied
		}
		if err = s.finalRawQuery(ctx, current, i, eligible.ValidUntil); err != nil {
			return zero, false, err
		}
		return g, true, nil
	}
	if !errors.Is(err, ErrGrantNotFound) {
		return zero, false, ErrGrantUnavailable
	}
	var selected RawQuerySelection
	if !slices.Contains(in.Operations, value.GrantDownloadOperation) {
		selector, ok := s.RawSelections.(RawPacketQuerySelectionReader)
		if !ok {
			return zero, false, ErrGrantUnavailable
		}
		selected, err = selector.ResolveRawPacketQuery(ctx, current, in.CaseID, in.ArtifactDigests)
	} else {
		selected, err = s.RawSelections.ResolveRawQuery(ctx, current, in.CaseID, in.ArtifactDigests)
	}
	if err != nil || !s.Now().Before(selected.ValidUntil) || len(selected.Artifacts) != len(in.ArtifactDigests) || len(selected.Review) != len(selected.Artifacts) {
		return zero, false, ErrGrantUnavailable
	}
	artifacts := slices.Clone(selected.Artifacts)
	slices.SortFunc(artifacts, func(a, b value.RawQueryArtifact) int {
		if a.Output.ArtifactID < b.Output.ArtifactID {
			return -1
		}
		if a.Output.ArtifactID > b.Output.ArtifactID {
			return 1
		}
		return 0
	})
	now := s.Now().UTC().Truncate(time.Microsecond)
	scope := value.RawQueryScope{CaseID: in.CaseID, Artifacts: artifacts, Operations: in.Operations, Reason: in.Reason, MaxBytes: in.MaxBytes, MaxOperations: value.GrantMaxResultOperations, NotAfter: now.Add(in.Lifetime)}
	if !scope.Valid(now) {
		return zero, false, value.ErrGrantInvalid
	}
	review := RawQueryReview{CaseID: in.CaseID, Artifacts: slices.Clone(selected.Review), Operations: slices.Clone(in.Operations), Reason: in.Reason, MaxBytes: in.MaxBytes, MaxOperations: value.GrantMaxResultOperations, NotAfter: scope.NotAfter}
	slices.SortFunc(review.Artifacts, func(a, b RawQueryReviewArtifact) int {
		if a.Output.ArtifactID < b.Output.ArtifactID {
			return -1
		}
		if a.Output.ArtifactID > b.Output.ArtifactID {
			return 1
		}
		return 0
	})
	selectedVersions := map[artifact.Digest]bool{}
	for n, a := range artifacts {
		r := review.Artifacts[n]
		if selectedVersions[a.Output.ArtifactDigest] || r.Output != a.Output || r.NativeBytes != a.NativeBytes || !r.ExpiresAt.Equal(a.ExpiresAt) || len(r.Namespace) > 253 || !identity.Text(r.NativeType, 128) || len(r.WorkloadKind) > 64 || len(r.WorkloadName) > 253 || len(r.PodName) > 253 || !slices.Contains(in.ArtifactDigests, a.Output.ArtifactDigest) {
			return zero, false, value.ErrGrantInvalid
		}
		selectedVersions[a.Output.ArtifactDigest] = true
	}
	g := value.Grant{ID: s.NewID(), RootID: s.RootID, Kind: value.GrantRawQuery, DataClass: "raw", Requester: i.Principal, RawQuery: &scope, Lifetime: in.Lifetime, Revision: 1, Reasons: []value.SensitiveReason{{ActionID: "download_artifact", Code: "rawDisclosure"}}}
	g.Scope, g.ExecutionDigest = RawQueryScopeBytes(scope)
	g.Review, err = json.Marshal(GrantReview{RawQuery: &review, Deadline: scope.NotAfter})
	if err != nil || len(g.Review) > value.GrantReviewBytesLimit(g.Kind) {
		return zero, false, value.ErrGrantInvalid
	}
	g.ReviewDigest = ReviewDigest(g, g.Review)
	probe := g
	probe.RequestedAt = now
	probe.ReviewUntil = now.Add(value.GrantReviewWindow)
	if !probe.Valid() || !RawQueryScopeMatches(probe) {
		return zero, false, value.ErrGrantInvalid
	}
	// Existing current approvals may cover the entire requested selection.
	if covering, ok, e := s.coveringRawSelection(ctx, i, scope); e != nil {
		return zero, false, e
	} else if ok {
		if err = s.finalRawQuery(ctx, current, i, selected.ValidUntil); err != nil {
			return zero, false, err
		}
		return covering, true, nil
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	until := identity.Earlier(selected.ValidUntil, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	if err = s.finalRawQuery(ctx, current, i, until); err != nil {
		return zero, false, err
	}
	effect, stop := context.WithDeadline(ctx, until)
	defer stop()
	out, replay, err := s.Store.RequestGrant(effect, StoredGrantRequest{Grant: g, IdempotencyKey: in.IdempotencyKey, RequestDigest: digest}, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.Requester != i.Principal || !RawQueryScopeMatches(out) || ReviewDigest(out, out.Review) != out.ReviewDigest {
		return zero, false, ErrGrantConflict
	}
	if err = s.finalRawQuery(effect, current, i, until); err != nil {
		return zero, false, err
	}
	return out, replay, nil
}

func (s GrantService) finalRawQuery(ctx context.Context, current identities.CurrentIdentity, original identity.Identity, until time.Time) error {
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !s.Now().Before(until) || !original.Valid(s.Now()) || !sameProjectionIdentity(cloneProjectionIdentity(original), final, s.Now()) {
		return identity.ErrDenied
	}
	return nil
}

func rawOutputForScope(g value.Grant, scope artifact.DownloadScope, actionID string) (value.VerifiedOutput, bool) {
	target := value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}
	if g.Kind == value.GrantRawQuery {
		if !RawQueryScopeMatches(g) {
			return value.VerifiedOutput{}, false
		}
		for _, a := range g.RawQuery.Artifacts {
			o := a.Output
			if o.CaptureID == scope.CaptureID && o.ArtifactID == scope.ArtifactID && o.ArtifactDigest == scope.Version && o.Target == target && (actionID == "" || o.ActionID == actionID) {
				return o, true
			}
		}
		return value.VerifiedOutput{}, false
	}
	if g.Kind != value.GrantAdHocCapture || g.CaptureID != scope.CaptureID || g.Target != target {
		return value.VerifiedOutput{}, false
	}
	return value.VerifiedOutput{CaptureID: scope.CaptureID, ArtifactID: scope.ArtifactID, ArtifactDigest: scope.Version, Target: target, ActionID: actionID, ExecutionDigest: g.ExecutionDigest}, true
}
func rawDownloadScope(root string, p identity.Principal, o value.VerifiedOutput) artifact.DownloadScope {
	return artifact.DownloadScope{RootID: root, CaptureID: o.CaptureID, ArtifactID: o.ArtifactID, Version: o.ArtifactDigest, ClusterID: o.Target.ClusterID, NamespaceUID: o.Target.NamespaceUID, WorkloadUID: o.Target.WorkloadUID, PodUID: o.Target.PodUID, Principal: p}
}
func (s GrantService) coveringRawSelection(ctx context.Context, i identity.Identity, selection value.RawQueryScope) (value.Grant, bool, error) {
	first := selection.Artifacts[0].Output
	// Reuse must permit at least one download per selected file, while
	// preserving the exact requested byte pool (including any retry allowance).
	operation := value.GrantDownloadOperation
	if !slices.Contains(selection.Operations, operation) {
		operation = value.GrantPacketQueryOperation
	}
	use := value.GrantUse{Operation: operation, Bytes: selection.MaxBytes, Operations: int64(len(selection.Artifacts))}
	candidates, err := s.RawStore.RawQueryCandidates(ctx, rawDownloadScope(s.RootID, i.Principal, first), use)
	if err != nil && !errors.Is(err, ErrGrantNotFound) {
		return value.Grant{}, false, ErrGrantUnavailable
	}
	legacy, err := s.Store.GrantByCapture(ctx, first.CaptureID)
	if err == nil && legacy.Kind == value.GrantAdHocCapture && legacy.DataClass == "raw" {
		candidates = append([]value.Grant{legacy}, candidates...)
	} else if err != nil && !errors.Is(err, ErrGrantNotFound) {
		return value.Grant{}, false, ErrGrantUnavailable
	}
	for _, g := range candidates {
		if !sameHuman(g.Requester, i.Principal) || g.Kind == value.GrantRawQuery && (g.Requester != i.Principal || !RawQueryScopeMatches(g)) || ReviewDigest(g, g.Review) != g.ReviewDigest || !value.PoolCovers(g, use) {
			continue
		}
		if g.Kind == value.GrantAdHocCapture && (g.ResultAccess == nil || g.ResultAccess.MaxArtifacts < len(selection.Artifacts)) {
			continue
		}
		covered := true
		var operations []string
		if g.Kind == value.GrantRawQuery {
			operations = g.RawQuery.Operations
		} else if g.ResultAccess != nil {
			operations = g.ResultAccess.Operations
		}
		for _, op := range selection.Operations {
			if !slices.Contains(operations, op) {
				covered = false
			}
		}
		for _, a := range selection.Artifacts {
			if value.CheckMaterialize(g, a.Output, i.Principal.ClientID, true, s.Now()) != nil {
				covered = false
				break
			}
		}
		if covered && g.Kind == value.GrantAdHocCapture {
			remaining := g.ResultAccess.MaxArtifacts - g.Spent.Artifacts
			if remaining < len(selection.Artifacts) {
				ids := make([]string, len(selection.Artifacts))
				for n, a := range selection.Artifacts {
					ids[n] = a.Output.ArtifactID
				}
				registered, err := s.RawStore.CountRegisteredGrantArtifacts(ctx, g.ID, ids)
				if err != nil || registered < 0 || registered > len(ids) {
					return value.Grant{}, false, ErrGrantUnavailable
				}
				covered = len(ids)-registered <= remaining
			}
		}
		if covered {
			return g, true, nil
		}
	}
	return value.Grant{}, false, nil
}

func (s GrantService) rawQueryEligibility(ctx context.Context, i identity.Identity, g value.Grant, op value.Operation) (value.Result, error) {
	if g.RawQuery != nil && op == value.DownloadApproved && !slices.Contains(g.RawQuery.Operations, value.GrantDownloadOperation) {
		op = value.ReadPacketQuery
	}
	if !g.Valid() || !RawQueryScopeMatches(g) || ReviewDigest(g, g.Review) != g.ReviewDigest {
		return value.Result{}, value.ErrGrantInvalid
	}
	result := value.Result{Eligible: true, Principal: i.Principal, ValidUntil: i.ValidUntil}
	seen := map[value.Target]bool{}
	for _, a := range g.RawQuery.Artifacts {
		if seen[a.Output.Target] {
			continue
		}
		seen[a.Output.Target] = true
		r, err := s.collector(ctx, i, a.Output.Target, op)
		if err != nil {
			return value.Result{}, err
		}
		if !r.Eligible {
			return r, nil
		}
		result.ValidUntil = identity.Earlier(result.ValidUntil, r.ValidUntil)
	}
	if !s.Now().Before(result.ValidUntil) {
		return value.Result{}, identity.ErrDenied
	}
	return result, nil
}

// rawParentFor first preserves an existing covering collection result grant,
// then considers exact existing-artifact approvals. CurrentResultAccess carries
// zero spend; reservations supply the actual use and never guess available bytes.
func (s GrantService) rawParentFor(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope, actionID string, use value.GrantUse, preparing bool) (identity.Identity, value.Grant, value.VerifiedOutput, error) {
	i, g, legacyErr := s.rawParent(ctx, current, scope)
	missing := errors.Is(legacyErr, value.ErrApprovalRequired)
	// A valid grant of another human is not their disclosure authority. A
	// malformed grant, bad digest or failed dependency remains unavailable.
	if preparing && errors.Is(legacyErr, value.ErrGrantPrincipal) && g.Valid() && ReviewDigest(g, g.Review) == g.ReviewDigest && i.Principal == scope.Principal {
		missing = true
	}
	if legacyErr == nil {
		output, ok := rawOutputForScope(g, scope, actionID)
		if !ok {
			legacyErr = value.ErrGrantScope
		} else if actionID != "" {
			legacyErr = value.CheckMaterialize(g, output, i.Principal.ClientID, true, s.Now())
			if preparing && g.Valid() && legacyErr != value.ErrGrantInvalid {
				r := g.ResultAccess
				if r == nil || !slices.Contains(r.ActionIDs, output.ActionID) || !slices.Contains(r.ClientIDs, i.Principal.ClientID) || !slices.Contains(r.Operations, value.GrantDownloadOperation) {
					missing = true
					if legacyErr == nil {
						legacyErr = value.ErrGrantScope
					}
				}
			}
		} else {
			child, e := s.Store.GrantChildFor(ctx, g.ID, scope.ArtifactID, i.Principal.ClientID)
			if e != nil {
				legacyErr = e
			} else if !childMatchesScope(child, scope) {
				legacyErr = value.ErrGrantScope
			} else {
				output = child.Output
				legacyErr = value.CheckResultUse(g, child, i, value.GrantDownloadOperation, s.Now())
			}
		}
		if legacyErr == nil && s.RawStore != nil && (use.Bytes > 0 || use.Operations > 0) && !value.PoolCovers(g, use) {
			legacyErr = value.ErrGrantPoolExhausted
		}
		if legacyErr == nil {
			return i, g, output, nil
		}
	}
	if preparing && (errors.Is(legacyErr, value.ErrGrantExpired) || errors.Is(legacyErr, value.ErrGrantRevoked) || errors.Is(legacyErr, value.ErrGrantDenied) || errors.Is(legacyErr, value.ErrGrantPoolExhausted)) {
		missing = true
	}
	if s.RawStore == nil {
		return identity.Identity{}, value.Grant{}, value.VerifiedOutput{}, legacyErr
	}
	if ctx == nil || ctx.Err() != nil || !s.ready() || !scope.Valid() || scope.RootID != s.RootID {
		return identity.Identity{}, value.Grant{}, value.VerifiedOutput{}, value.ErrGrantInvalid
	}
	var err error
	i, err = s.human(ctx, current, "evidence:download")
	if err != nil {
		return i, value.Grant{}, value.VerifiedOutput{}, err
	}
	if i.Principal != scope.Principal {
		return i, value.Grant{}, value.VerifiedOutput{}, value.ErrGrantPrincipal
	}
	candidates, err := s.RawStore.RawQueryCandidates(ctx, scope, use)
	if err != nil && !errors.Is(err, ErrGrantNotFound) {
		return i, value.Grant{}, value.VerifiedOutput{}, ErrGrantUnavailable
	}
	incomplete := false
	for _, candidate := range candidates {
		if candidate.Kind != value.GrantRawQuery || candidate.Requester != i.Principal || ReviewDigest(candidate, candidate.Review) != candidate.ReviewDigest {
			incomplete = true
			continue
		}
		output, ok := rawOutputForScope(candidate, scope, actionID)
		if !ok {
			incomplete = true
			continue
		}
		if check := value.CheckMaterialize(candidate, output, i.Principal.ClientID, true, s.Now()); check != nil {
			incomplete = incomplete || errors.Is(check, value.ErrGrantInvalid)
			continue
		}
		if (use.Bytes > 0 || use.Operations > 0) && !value.PoolCovers(candidate, use) {
			continue
		}
		return i, candidate, output, nil
	}
	if preparing && missing && !incomplete {
		return i, value.Grant{}, value.VerifiedOutput{}, value.ErrApprovalRequired
	}
	if preparing && incomplete {
		return i, value.Grant{}, value.VerifiedOutput{}, ErrGrantUnavailable
	}
	return i, value.Grant{}, value.VerifiedOutput{}, legacyErr
}
