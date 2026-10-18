package capacity

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// QueryCapacitySource is read from the original protected SQL setup and current
// accepted capacity source, not supplied by the person requesting an excerpt.
type QueryCapacitySource struct {
	Qualification          CapacityQualification
	Root                   RootConfiguration
	System                 ProtectedPoolPlan
	AcceptanceID           string
	ObservationCount       int64
	Ready                  bool
	BackingUntil           time.Time
	SetupInputDigest       artifact.Digest
	SourceRevision         int64
	SourceDigest           artifact.Digest
	Recovery               artifact.RecoveryProof
	ObservedAt, FreshUntil time.Time
}

func (s QueryCapacitySource) Valid(now time.Time) bool {
	return s.Qualification.Valid() && s.Qualification.ContextQuery != nil && s.Root.AdmissionReady(now) &&
		s.ObservationCount >= 0 && s.ObservationCount <= s.Qualification.ContextQuery.SourceTransitionLimit+1 &&
		s.Root.RootID == s.Qualification.RootBacking.RootID && (s.AcceptanceID == "" || authorization.UUID(s.AcceptanceID)) &&
		s.SetupInputDigest != (artifact.Digest{}) && s.SourceRevision > 0 && s.SourceDigest != (artifact.Digest{}) &&
		s.Recovery.Valid(now) && s.Recovery.InstallationID == s.Qualification.RootBacking.InstallationID &&
		identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) && !s.FreshUntil.After(s.Recovery.FreshUntil)
}

type QueryCapacityReader interface {
	ReadQueryCapacitySource(context.Context, artifact.RecoveryProof) (QueryCapacitySource, error)
	ReadQueryCapacityPlan(context.Context, QueryCapacitySource, value.ContextProjectionAuthority, string) (value.ContextQueryPlan, error)
}
type QueryCapacityWriter interface {
	BeginQueryCapacityObservation(context.Context, QueryCapacitySource, QueryBackingPlan, string) (QueryCapacityObservation, error)
	AcceptQueryCapacity(context.Context, QueryCapacitySource, QueryBackingPlan, QueryCapacityObservation) (QueryBackingPlan, error)
	CompleteQueryCapacityObservation(context.Context, QueryCapacityObservation) error
	AllocateQueryCapacity(context.Context, QueryBackingPlan, WorkloadCapacityKey, string) (string, error)
	SuspendQueryCapacity(context.Context, time.Time) error
}

// Acknowledged pre-I/O source work, not a positive accepted source. Unknown
// reservations remain spent. Only the exact original interval may be finalized.
type QueryCapacityObservation struct {
	ID, AcceptanceID       string
	Ordinal                int64
	ObservedAt, ValidUntil time.Time
}

func (o QueryCapacityObservation) Valid(source QueryCapacitySource, plan QueryBackingPlan, now time.Time) bool {
	return authorization.UUID(o.ID) && o.AcceptanceID == plan.AcceptanceID && o.Ordinal > 0 && o.Ordinal <= plan.Qualification.SourceTransitionLimit &&
		identity.Fresh(o.ObservedAt, o.ValidUntil, now, 5*time.Second) && !o.ObservedAt.Before(source.ObservedAt) && !o.ValidUntil.After(source.FreshUntil)
}

type QueryRecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// A guard independently validates accepted native source continuity, exact
// measured report/profile provenance and CURRENT enforced deployment limits.
// It must reject known changes/negative watermarks, suspension, recovery, and
// unqualified limits. It holds the original <=5s context through one callback
// and final checks. A configuration struct, report digest or worker proof alone
// cannot implement this contract for another deployment. Return only after all
// owned native I/O and callback work have joined, including failure paths.
type QueryDeploymentGuard interface {
	WithCurrentQueryDeployment(context.Context, ContextQueryQualification, QueryDeploymentPin, func(context.Context) error) error
}

type QueryDeploymentGuards struct{ Worker, Hub, KeyService, Provider QueryDeploymentGuard }

func (g QueryDeploymentGuards) with(ctx context.Context, q ContextQueryQualification, fn func(context.Context) error) error {
	if g.Worker == nil || g.Hub == nil || g.KeyService == nil || g.Provider == nil || ctx == nil || ctx.Err() != nil || fn == nil {
		return value.ErrUnavailable
	}
	guards := []QueryDeploymentGuard{g.Worker, g.Hub, g.KeyService, g.Provider}
	pins := []QueryDeploymentPin{q.Native.Worker, q.Native.Hub, q.Native.KeyService, q.Native.Provider}
	var run func(int, context.Context) error
	run = func(i int, parent context.Context) error {
		if i == len(guards) {
			return fn(parent)
		}
		// Serialize and join callback ownership. Omitted/repeated callbacks,
		// callbacks observed after guard return, and replaced contexts cannot
		// create a success. Guards separately own joining their native I/O.
		var mu sync.Mutex
		called, returned := false, false
		var originalUntil time.Time
		var callbackErr error
		// A provider cannot mutate the source snapshot retained by C-07.
		encoded, err := json.Marshal(q)
		var guardQualification ContextQueryQualification
		if err != nil || json.Unmarshal(encoded, &guardQualification) != nil {
			return value.ErrUnavailable
		}
		e := guards[i].WithCurrentQueryDeployment(parent, guardQualification, pins[i], func(child context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			if called || returned || child == nil || parent.Err() != nil || child.Err() != nil {
				callbackErr = value.ErrUnavailable
				return callbackErr
			}
			called = true
			// Context values/cancellation remain parent-owned. Child may shorten,
			// never replace them. Join cancellation callback before returning.
			bound, cancel := context.WithCancel(parent)
			joined := make(chan struct{})
			stop := context.AfterFunc(child, func() { cancel(); close(joined) })
			defer func() {
				if !stop() {
					<-joined
				}
				cancel()
			}()
			if d, ok := child.Deadline(); ok {
				originalUntil = d
				var c context.CancelFunc
				bound, c = context.WithDeadline(bound, d)
				defer c()
			}
			callbackErr = run(i+1, bound)
			if bound.Err() != nil {
				callbackErr = value.ErrUnavailable
			}
			return callbackErr
		})
		mu.Lock()
		returned = true
		valid := called && callbackErr == nil
		mu.Unlock()
		if e != nil || !valid || parent.Err() != nil || !originalUntil.IsZero() && !time.Now().Before(originalUntil) {
			return value.ErrUnavailable
		}
		return nil
	}
	return run(0, ctx)
}

// ProtectedContextQueryCapacity is shared private C-07 composition. The store
// independently verifies original installed provenance and residual arithmetic;
// four deployment guards supply current external proof outside SQL locks. No
// public request chooses qualification, resource dimensions or another path.
type ProtectedContextQueryCapacity struct {
	RootID, InstallationID string
	Store                  QueryCapacityReader
	Recovery               QueryRecoveryReader
	Deployments            QueryDeploymentGuards
	Now                    func() time.Time
	NewID                  func() string
}

func (s ProtectedContextQueryCapacity) current(ctx context.Context, requireBacking bool, fn func(context.Context, QueryCapacitySource) error) error {
	return s.currentWithStart(ctx, requireBacking, nil, fn)
}

func (s ProtectedContextQueryCapacity) currentWithStart(ctx context.Context, requireBacking bool, begin func(context.Context, QueryCapacitySource) (QueryCapacitySource, error), fn func(context.Context, QueryCapacitySource) error) error {
	if ctx == nil || ctx.Err() != nil || s.Store == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return value.ErrUnavailable
	}
	original, cancel := context.WithDeadline(ctx, s.Now().Add(5*time.Second))
	defer cancel()
	recovery, e := s.Recovery.RecoveryState(original)
	if e != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID {
		return value.ErrUnavailable
	}
	original, c1 := context.WithDeadline(original, recovery.FreshUntil)
	defer c1()
	source, e := s.Store.ReadQueryCapacitySource(original, recovery)
	if e != nil || !source.Valid(s.Now()) || source.Root.RootID != s.RootID || source.Qualification.RootBacking.InstallationID != s.InstallationID || source.Recovery != recovery {
		return value.ErrUnavailable
	}
	if requireBacking {
		if !source.Ready || source.AcceptanceID == "" || !s.Now().Before(source.BackingUntil) {
			return value.ErrUnavailable
		}
		// A consumer retains the first accepted backing bound before any
		// external guard, plan lookup or final source read can block. The
		// separate producer obtains a new observation from current protected
		// sources; it never changes this consumer's original bound.
		var stop context.CancelFunc
		original, stop = context.WithDeadline(original, source.BackingUntil)
		defer stop()
	}
	original, c2 := context.WithDeadline(original, source.FreshUntil)
	defer c2()
	if d, ok := original.Deadline(); ok {
		source.FreshUntil = identity.Earlier(source.FreshUntil, d)
	}
	// Snapshot before any external guard. The accepted source and profile are
	// immutable during this operation even if a port retains its input slices.
	encoded, e := json.Marshal(source)
	source = QueryCapacitySource{}
	if e != nil || json.Unmarshal(encoded, &source) != nil {
		return value.ErrUnavailable
	}
	if begin != nil {
		// The irreversible claim must be acknowledged before any native guard.
		// A failed/unknown begin grants no work; its durable spend is retained.
		source, e = begin(original, source)
		if e != nil || !source.Valid(s.Now()) || original.Err() != nil {
			return value.ErrUnavailable
		}
		var stop context.CancelFunc
		original, stop = context.WithDeadline(original, source.FreshUntil)
		defer stop()
	}
	e = s.Deployments.with(original, *source.Qualification.ContextQuery, func(bound context.Context) error {
		if d, ok := bound.Deadline(); ok {
			source.FreshUntil = identity.Earlier(source.FreshUntil, d)
		}
		if !source.Valid(s.Now()) || bound.Err() != nil {
			return value.ErrUnavailable
		}
		if e := fn(bound, source); e != nil {
			return e
		}
		last, e := s.Store.ReadQueryCapacitySource(bound, recovery)
		// This operation has already used source.FreshUntil, narrowed to the
		// caller, first backing and all guard bounds. A later shorter source
		// cannot leave that result live while outer guards finish. Reject it;
		// do not rewrite prepared effects or extend any original observation.
		if e != nil || !last.Valid(s.Now()) || !sameQuerySource(source, last) || source.Ready && !last.Ready ||
			last.FreshUntil.Before(source.FreshUntil) || requireBacking && last.BackingUntil.Before(source.FreshUntil) ||
			!source.Valid(s.Now()) || bound.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || original.Err() != nil || !source.Valid(s.Now()) {
		return value.ErrUnavailable
	}
	return nil
}

func sameQuerySource(a, b QueryCapacitySource) bool {
	if a.ObservationCount != b.ObservationCount || a.Root.AttemptID != b.Root.AttemptID || a.Root.PlanDigest != b.Root.PlanDigest || a.SetupInputDigest != b.SetupInputDigest || a.SourceDigest != b.SourceDigest || a.SourceRevision != b.SourceRevision || a.Recovery.InstallationID != b.Recovery.InstallationID || a.Recovery.IssuerEpoch != b.Recovery.IssuerEpoch || a.Recovery.Revision != b.Recovery.Revision || a.AcceptanceID != "" && a.AcceptanceID != b.AcceptanceID {
		return false
	}
	x, _ := json.Marshal(a.Qualification)
	y, _ := json.Marshal(b.Qualification)
	return string(x) == string(y)
}

// Reconcile accepts the one original reservation and, optionally, an exact
// already protected workload slot. It never discovers/replaces a workload or
// authorizes collection. Unknown writes retain their original identity/charge;
// an unresolved claim stays held instead of minting a replacement epoch.
type ProtectedContextQueryProducer struct {
	Current ProtectedContextQueryCapacity
	Writer  QueryCapacityWriter
}

func (p ProtectedContextQueryProducer) Reconcile(ctx context.Context, key *WorkloadCapacityKey) error {
	s := p.Current
	if s.NewID == nil || p.Writer == nil {
		return value.ErrUnavailable
	}
	var plan QueryBackingPlan
	var attempt QueryCapacityObservation
	var finalUntil time.Time
	owned := false
	err := s.currentWithStart(ctx, false, func(bound context.Context, source QueryCapacitySource) (QueryCapacitySource, error) {
		if source.ObservationCount >= source.Qualification.ContextQuery.SourceTransitionLimit {
			return QueryCapacitySource{}, value.ErrUnavailable
		}
		acceptance := source.AcceptanceID
		if acceptance == "" {
			acceptance = s.NewID()
		}
		base, e := CompileQualifiedRootBacking(source.Qualification, source.System)
		if e != nil {
			return QueryCapacitySource{}, e
		}
		plan, e = CompileQueryBacking(source.Qualification, source.Root, base, source.System, source.SetupInputDigest, acceptance)
		if e != nil {
			return QueryCapacitySource{}, e
		}
		attemptID := s.NewID()
		attempt, e = p.Writer.BeginQueryCapacityObservation(bound, source, plan, attemptID)
		if e != nil || !attempt.Valid(source, plan, s.Now()) || attempt.ID != attemptID || attempt.Ordinal != source.ObservationCount+1 || bound.Err() != nil {
			return QueryCapacitySource{}, value.ErrUnavailable
		}
		owned = true
		source.AcceptanceID, source.ObservationCount = acceptance, attempt.Ordinal
		source.ObservedAt, source.FreshUntil = attempt.ObservedAt, attempt.ValidUntil
		return source, nil
	}, func(bound context.Context, source QueryCapacitySource) error {
		finalUntil = source.FreshUntil
		accepted, e := p.Writer.AcceptQueryCapacity(bound, source, plan, attempt)
		if e != nil {
			return e
		}
		x, _ := json.Marshal(plan)
		y, _ := json.Marshal(accepted)
		if string(x) != string(y) {
			return value.ErrUnavailable
		}
		if key != nil {
			if key.RootID != s.RootID {
				return value.ErrUnavailable
			}
			_, e = p.Writer.AllocateQueryCapacity(bound, accepted, *key, s.NewID())
			if e != nil {
				return e
			}
		}
		return nil
	})
	if !owned {
		return value.ErrUnavailable
	}
	// All native guards have now returned and joined their work. A known failed
	// guard may release only this private claim, never accept or renew authority.
	// Cleanup retains the original prepaid claim cutoff when caller cancellation
	// caused the failure. Unknown Begin never yields this completion capability.
	until := attempt.ValidUntil
	if err == nil {
		until = identity.Earlier(until, finalUntil)
	}
	if until.IsZero() || !s.Now().Before(until) {
		return value.ErrUnavailable
	}
	end, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	defer cancel()
	if e := p.Writer.CompleteQueryCapacityObservation(end, attempt); e != nil || end.Err() != nil || !s.Now().Before(until) {
		return value.ErrUnavailable
	}
	if err != nil || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}

func (s ProtectedContextQueryCapacity) ContextQueryPlan(ctx context.Context, a value.ContextProjectionAuthority) (value.ContextQueryPlan, error) {
	var out value.ContextQueryPlan
	if ctx == nil || s.Now == nil || s.NewID == nil || !a.Valid(s.Now()) || a.Scope.RootID != s.RootID {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, a.ValidUntil)
	defer cancel()
	e := s.current(ctx, true, func(bound context.Context, source QueryCapacitySource) error {
		if !source.Ready || !s.Now().Before(source.BackingUntil) {
			return value.ErrUnavailable
		}
		var e error
		out, e = s.Store.ReadQueryCapacityPlan(bound, source, a, s.NewID())
		// The final source read and outer guards retain this effective bound.
		// Reject a newly shorter plan before either can block under it.
		if e != nil || !out.Valid(a.Scope, s.Now()) || out.ValidUntil.Before(source.FreshUntil) || out.Profile != source.Qualification.ContextQuery.Profile {
			return value.ErrUnavailable
		}
		out.ValidUntil = identity.Earlier(out.ValidUntil, identity.Earlier(source.FreshUntil, source.BackingUntil))
		return nil
	})
	if e != nil || !out.Valid(a.Scope, s.Now()) {
		return value.ContextQueryPlan{}, value.ErrUnavailable
	}
	return out, nil
}

func (s ProtectedContextQueryCapacity) WithCurrentQueryBacking(ctx context.Context, p value.ContextQueryPlan, a value.ContextProjectionAuthority, callback func(context.Context) error) error {
	// The stored plan's observation is historical during a later paid poll.
	// Current authority and a NEW protected observation bound this invocation;
	// the original accepted profile and hard/effect/history dates stay exact.
	if ctx == nil || s.Now == nil || callback == nil || !p.Matches(a.Scope) || !a.Valid(s.Now()) {
		return value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, a.ValidUntil)
	defer cancel()
	var originalUntil time.Time
	err := s.current(ctx, true, func(bound context.Context, source QueryCapacitySource) error {
		if !source.Ready || !s.Now().Before(source.BackingUntil) || source.AcceptanceID != p.AcceptanceID || source.Qualification.ContextQuery.Profile != p.Profile {
			return value.ErrUnavailable
		}
		current, e := s.Store.ReadQueryCapacityPlan(bound, source, a, p.AccountID)
		// source.FreshUntil already includes caller/authority/guard cutoffs.
		// A newly earlier plan cannot safely flow into effects followed by the
		// outer source read under the previously longer effective bound.
		if e != nil || !current.Valid(a.Scope, s.Now()) || current.ValidUntil.Before(source.FreshUntil) || !sameQueryPlan(p, current) {
			return value.ErrUnavailable
		}
		originalUntil = identity.Earlier(current.ValidUntil, source.FreshUntil)
		bound, cancel := context.WithDeadline(bound, originalUntil)
		defer cancel()
		if e = callback(bound); e != nil {
			return e
		}
		last, e := s.Store.ReadQueryCapacityPlan(bound, source, a, p.AccountID)
		if e != nil || !last.Valid(a.Scope, s.Now()) || last.ValidUntil.Before(originalUntil) || !sameQueryPlan(p, last) || bound.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || originalUntil.IsZero() || !s.Now().Before(originalUntil) {
		return value.ErrUnavailable
	}
	return nil
}

func sameQueryPlan(a, b value.ContextQueryPlan) bool {
	a.ObservedAt = b.ObservedAt
	a.ValidUntil = b.ValidUntil
	return a == b
}

func (s ProtectedContextQueryCapacity) ContextProjectionPolicy(ctx context.Context) (value.ContextProjectionPolicy, error) {
	var out value.ContextProjectionPolicy
	e := s.current(ctx, true, func(bound context.Context, source QueryCapacitySource) error {
		if !source.Ready || !s.Now().Before(source.BackingUntil) || source.AcceptanceID == "" {
			return value.ErrUnavailable
		}
		q := source.Qualification.ContextQuery
		out = value.ContextProjectionPolicy{RootID: s.RootID, InstallationID: s.InstallationID, RecoveryEpoch: source.Recovery.IssuerEpoch, Revision: q.PolicyRevision, ProtectionDigest: source.SetupInputDigest, Path: q.Profile.Path, PermittedRegions: append([]string{}, q.PermittedRegions...), Clients: q.Clients, ObservedAt: source.ObservedAt, FreshUntil: identity.Earlier(source.FreshUntil, source.BackingUntil)}
		return nil
	})
	if e != nil || !out.Valid(s.Now()) {
		return value.ContextProjectionPolicy{}, value.ErrUnavailable
	}
	return out, nil
}
