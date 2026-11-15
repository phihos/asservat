package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// Narrow ports consume existing request-owned identity and protected policy;
// they introduce neither a new identity evaluator nor a public management API.
type ProcessingIdentity interface {
	ResolveIdentity(context.Context) (identity.Identity, error)
}
type ProcessingPolicyReader interface {
	DownloadPolicy(context.Context) (value.DownloadPolicy, error)
}

// ProcessingDecisions applies a decision and writes its audit row in one SQL
// transaction (REQ-AUT-005). A replay of the request ID returns the existing
// receipt and writes no second row.
type ProcessingDecisions interface {
	ApplyProcessing(context.Context, value.ProcessingAuthority, ProcessingDecision) (value.ProcessingReceipt, error)
}
type ProcessingArtifactScopes interface {
	ResolveProcessingArtifactScope(context.Context, value.ProcessingAuthority, string) (value.ProcessingScope, error)
}
type ProcessingChanges struct {
	RootID, InstallationID string
	Policies               ProcessingPolicyReader
	Decisions              ProcessingDecisions
	ArtifactScopes         ProcessingArtifactScopes
	Now                    func() time.Time
}

// ProcessingDecision is one change with its original request interval.
type ProcessingDecision struct {
	Change                  value.ProcessingChange
	CreatedAt, RequestUntil time.Time
}

func (d ProcessingDecision) Valid() bool {
	return d.Change.Valid() && !d.CreatedAt.IsZero() && d.RequestUntil.After(d.CreatedAt) && !d.RequestUntil.After(d.CreatedAt.Add(5*time.Second))
}

func (s ProcessingChanges) authority(ctx context.Context, source ProcessingIdentity, started, until time.Time) (value.ProcessingAuthority, error) {
	var zero value.ProcessingAuthority
	i, e := source.ResolveIdentity(ctx)
	if e != nil || !i.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	p, e := s.Policies.DownloadPolicy(ctx)
	now := s.Now()
	if e != nil || ctx.Err() != nil || p.RootID != s.RootID || p.InstallationID != s.InstallationID || !p.Valid(now) || !i.Valid(now) {
		return zero, value.ErrUnavailable
	}
	if !p.Operator(i, now) {
		return zero, identity.ErrDenied
	}
	until = identity.Earlier(until, identity.Earlier(i.ValidUntil, p.FreshUntil))
	a := value.ProcessingAuthority{Identity: i, Policy: p, ObservedAt: started, ValidUntil: until}
	if ctx.Err() != nil || !a.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	return a, nil
}

// Change checks authority once (ADR-311) and applies the decision.
func (s ProcessingChanges) Change(ctx context.Context, source ProcessingIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	var zero value.ProcessingReceipt
	if ctx == nil || ctx.Err() != nil || source == nil || s.Policies == nil || s.Decisions == nil || s.Now == nil || !c.ValidRequest() {
		return zero, value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d).UTC().Truncate(time.Microsecond)
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	authority, e := s.authority(call, source, started, until)
	if e != nil {
		return zero, e
	}
	until = authority.ValidUntil.UTC().Truncate(time.Microsecond)
	call, stopOriginal := context.WithDeadline(call, until)
	defer stopOriginal()
	if c.RequestedArtifactID != "" {
		if s.ArtifactScopes == nil {
			return zero, value.ErrUnavailable
		}
		scope, err := s.ArtifactScopes.ResolveProcessingArtifactScope(call, authority, c.RequestedArtifactID)
		if err != nil || !authority.Valid(s.Now()) || call.Err() != nil || scope.Kind != "artifact" || scope.Location.ArtifactID != c.RequestedArtifactID || !scope.Valid() {
			return zero, value.ErrUnavailable
		}
		c.Scope, c.RequestedArtifactID = scope, ""
	}
	decision := ProcessingDecision{Change: c, CreatedAt: started, RequestUntil: until}
	if !decision.Valid() {
		return zero, value.ErrUnavailable
	}
	result, e := s.Decisions.ApplyProcessing(call, authority, decision)
	switch {
	case errors.Is(e, value.ErrConflict):
		return zero, value.ErrConflict
	case errors.Is(e, ErrCapacity):
		return zero, ErrCapacity
	case e != nil || !result.Valid(s.Now()) || result.RequestID != c.RequestID || call.Err() != nil:
		return zero, value.ErrUnavailable
	}
	return result, nil
}

func ProcessingRequestDigest(c value.ProcessingChange) artifact.Digest {
	b, e := json.Marshal(c)
	if e != nil || !c.Valid() {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}

func sameProcessingIdentity(a, b identity.Identity) bool {
	if a.Principal != b.Principal || a.Policy != b.Policy {
		return false
	}
	x, y := slices.Clone(a.Groups), slices.Clone(b.Groups)
	slices.Sort(x)
	slices.Sort(y)
	if !slices.Equal(x, y) {
		return false
	}
	x, y = slices.Clone(a.Scopes), slices.Clone(b.Scopes)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// Reuse one complete operation observation, preserving every original bound.
// ResolveIdentity checks the existing request identity; policy is not
// observed again and SQL retains its independent current effect checks.
func (s ProcessingChanges) continueAuthority(ctx context.Context, source ProcessingIdentity, original value.ProcessingAuthority) (value.ProcessingAuthority, error) {
	current, err := source.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !original.Valid(s.Now()) || !current.Valid(s.Now()) || !sameProcessingIdentity(original.Identity, current) {
		return value.ProcessingAuthority{}, value.ErrUnavailable
	}
	original.ValidUntil = identity.Earlier(original.ValidUntil, current.ValidUntil)
	if !original.Valid(s.Now()) {
		return value.ProcessingAuthority{}, value.ErrUnavailable
	}
	return original, nil
}
