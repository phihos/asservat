package kubernetes

import (
	"context"
	"errors"
	"sync"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// One fixed implementation satisfies both existing purpose-specific seams.
// No callback, public source DTO, arbitrary stage or retry policy is accepted.
type OwnerInstallationSQL interface {
	OwnerIdentityRoleOperationCreation
	OwnerIdentityOperationVerification
}

type OwnerInstallationResult struct {
	Complete        bool // historical invocation completion, never current runtime authority
	Stop            OwnerInstallationStop
	Phase           string
	OperationID     string
	RoleRootUID     string
	ResourceRootUID string
	Calls           int
	Inspections     int
	Finalizations   int
	Brackets        int // installation brackets opened (ADR-316)
}

// ProviderOwnerInstallation is a single invocation of the original fixed
// installation. Its owned cancellation/join retains the caller-owned root,
// resources and concrete SQL adapter through all admitted work; callers close
// those dependencies only after Run or Close joins. It does not run a Pod or
// assert runtime readiness after the positive launch receipt.
type ProviderOwnerInstallation struct {
	mu         sync.Mutex
	work       sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
	closed     bool
	projection *ProviderOwnerProjection
	sql        OwnerInstallationSQL
	reserve    time.Duration // bracket reserve; tests raise it to one operation per bracket
}

func NewProviderOwnerInstallation(projection *ProviderOwnerProjection, sql OwnerInstallationSQL) (*ProviderOwnerInstallation, error) {
	if projection == nil || projection.projection == nil || projection.projection.root == nil || sql == nil {
		return nil, cfg.ErrInvalid
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ProviderOwnerInstallation{ctx: ctx, cancel: cancel, projection: projection, sql: sql, reserve: ownerInstallationBracketReserve}, nil
}

func (s *ProviderOwnerInstallation) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.work.Wait()
}

func (s *ProviderOwnerInstallation) Run(ctx context.Context) (result OwnerInstallationResult, failure error) {
	out := OwnerInstallationResult{Phase: "role-root"}
	if s == nil || ctx == nil {
		out.Stop = OwnerInstallationClosed
		return out, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.started || s.closed || s.ctx == nil || s.ctx.Err() != nil || ctx.Err() != nil {
		s.mu.Unlock()
		out.Stop = OwnerInstallationClosed
		return out, cfg.ErrUnavailable
	}
	s.started = true
	s.work.Add(1)
	s.mu.Unlock()
	defer s.work.Done()
	call, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { cancel(); close(joined) })
	finishCaller := sync.OnceFunc(func() {
		cancel()
		if !stop() {
			<-joined
		}
	})
	defer finishCaller()
	call, release, err := s.projection.projection.borrowProviderCall(call)
	if err != nil {
		out.Stop = OwnerInstallationUnverified
		return out, err
	}
	release = sync.OnceFunc(release)
	root := s.projection.projection.root
	defer func() {
		// Complete is historical, but original cancellation still wins if
		// releasing and joining the outer borrow delays this return.
		release()
		finishCaller()
		if failure == nil && result.Complete && (ctx.Err() != nil || s.ctx.Err() != nil || root.ctx.Err() != nil || root.resources.ctx.Err() != nil) {
			result.Complete = false
			result.Stop = OwnerInstallationCancelled
			failure = cfg.ErrUnavailable
		}
	}()
	var originalEnd time.Time
	fail := func(err error) (OwnerInstallationResult, error) {
		out.Stop = OwnerInstallationUnverified
		var phase *ownerInstallationPhaseError
		if errors.As(err, &phase) {
			out.Stop = phase.stop
			out.OperationID = phase.operationID
		}
		if !originalEnd.IsZero() && !root.resources.now().Before(originalEnd) {
			out.Stop = OwnerInstallationExpired
		} else if call.Err() != nil {
			out.Stop = OwnerInstallationCancelled
		}
		return out, err
	}
	// Twenty-two original transitions (open, two per identity role, projection
	// and launch steps) plus eight required read-only finalizations,
	// and at most one independent unknown-result inspection.
	// These counters are invocation-wide, not a per-phase retry allowance.
	normalCalls := 0
	normal := func(ctx context.Context) bool {
		if normalCalls >= 22 || ctx.Err() != nil {
			return false
		}
		out.Calls++
		normalCalls++
		return true
	}
	inspect := func(ctx context.Context, err error) bool {
		var phase *ownerInstallationPhaseError
		if errors.As(err, &phase) && phase.stop == OwnerInstallationSpent {
			return false
		}
		if out.Inspections != 0 || ctx.Err() != nil || !originalEnd.IsZero() && !root.resources.now().Before(originalEnd) {
			return false
		}
		out.Inspections++
		out.Calls++
		return true
	}
	// One projection or launch execution and its mandatory finalization; both
	// run under the same caller context, which bounds the finalization.
	pair := func(ctx context.Context, execute func(context.Context) error) (OwnerProjectionAdvance, error) {
		e := execute(ctx)
		var result OwnerProjectionAdvance
		if e != nil {
			if inspect(ctx, e) {
				first := projectionFixedCodes(e)
				out.Finalizations++
				result, e = s.projection.Finalize(ctx)
				if e != nil {
					e = &ownerProjectionInspectionDiagnostic{cause: e, first: first, inspection: projectionFixedCodes(e)}
				}
			}
		} else {
			if out.Finalizations >= 8 {
				return result, cfg.ErrUnavailable
			}
			out.Calls++
			out.Finalizations++
			result, e = s.projection.Finalize(ctx)
		}
		return result, e
	}
	// The fixed sequence as one operation per step, so that operations sharing
	// the same opening proof run in installation brackets (ADR-316).
	var roles contracts.OwnerIdentityRoleSnapshot
	stage, role, rolePhase, projectionPhase, launchPhase, rank := 0, 0, 0, 0, 0, -1
	inBracket := 0
	step := func(ctx context.Context) (more bool, err error) {
		defer func() {
			if more {
				inBracket++
			}
		}()
		if !originalEnd.IsZero() {
			var end context.CancelFunc
			ctx, end = context.WithDeadline(ctx, originalEnd)
			defer end()
		}
		for {
			switch stage {
			case 0:
				if !normal(ctx) {
					return false, cfg.ErrUnavailable
				}
				opened, err := root.OpenProviderOwnerIdentityRoles(ctx)
				if err != nil && inspect(ctx, err) {
					opened, err = root.InspectProviderOwnerIdentityRoles(ctx)
				}
				if err != nil {
					return false, err
				}
				roles, originalEnd = opened, opened.State.Until
				out.RoleRootUID = opened.UID
				if !root.resources.now().Before(originalEnd) {
					return false, cfg.ErrUnavailable
				}
				stage = 1
				return true, nil
			case 1:
				purposes := contracts.OwnerIdentityRolePurposes()
				if role == len(purposes) {
					stage = 2
					continue
				}
				purpose := purposes[role]
				out.Phase = purpose
				if roles.State.Roles[role].Receipt != nil {
					role++
					continue
				}
				if rolePhase == 2 {
					return false, cfg.ErrUnavailable
				}
				if !normal(ctx) {
					return false, cfg.ErrUnavailable
				}
				rolePhase++
				result, e := root.AdvanceProviderOwnerIdentityRole(ctx, purpose, s.sql)
				if e != nil && inspect(ctx, e) {
					result, e = root.InspectProviderOwnerIdentityRole(ctx, purpose, s.sql)
				}
				if e != nil {
					return false, e
				}
				roles = result.Snapshot
				if result.Status == OwnerIdentityRoleAdvanceComplete && roles.State.Roles[role].Receipt != nil {
					role, rolePhase = role+1, 0
					return true, nil
				}
				if result.Status != OwnerIdentityRoleAdvancePending || roles.State.Roles[role].Claim == nil || roles.State.Roles[role].Receipt != nil {
					return false, cfg.ErrChanged
				}
				return true, nil
			case 2:
				out.Phase = "verify-four-roles"
				if !normal(ctx) {
					return false, cfg.ErrUnavailable
				}
				_, err := root.VerifyProviderOwnerIdentityRoles(ctx, s.sql)
				if err != nil && inspect(ctx, err) {
					_, err = root.VerifyProviderOwnerIdentityRoles(ctx, s.sql)
				}
				if err != nil {
					return false, err
				}
				out.Phase, stage = "projection", 3
				return true, nil
			case 3:
				if projectionPhase == 6 || !normal(ctx) {
					return false, cfg.ErrUnavailable
				}
				projectionPhase++
				result, e := pair(ctx, s.projection.Execute)
				if e != nil {
					return false, e
				}
				next := ownerInstallationProjectionRank(result.Snapshot.State.OwnerIdentity)
				if next <= rank {
					return false, cfg.ErrChanged
				}
				rank = next
				out.ResourceRootUID = result.Snapshot.UID
				if rank == 6 && result.Status == OwnerProjectionAdvanceComplete {
					out.Phase, stage = "launch", 4
					return true, nil
				}
				if rank == 6 || result.Status == OwnerProjectionAdvanceComplete {
					return false, cfg.ErrChanged
				}
				return true, nil
			case 4:
				// Every launch attempt opens its own bracket so a complete proof
				// directly precedes the workload-starting effect.
				if inBracket > 0 {
					return false, nil
				}
				if launchPhase == 2 || !normal(ctx) {
					return false, cfg.ErrUnavailable
				}
				launchPhase++
				result, e := pair(ctx, s.projection.ExecuteLaunch)
				if e != nil {
					return false, e
				}
				claim := result.Snapshot.State.OwnerLaunch
				if claim == nil {
					return false, cfg.ErrChanged
				}
				out.OperationID = claim.OperationID
				if result.Status == OwnerProjectionAdvanceComplete && claim.Receipt != nil {
					out.Phase, stage = "launch-receipt", 5
					return true, nil
				}
				if result.Status != OwnerProjectionAdvancePending || claim.Receipt != nil {
					return false, cfg.ErrChanged
				}
				return true, nil
			default:
				return false, nil
			}
		}
	}
	// Each bracket opens with one complete native proof of the protected root
	// and closes with another after its last operation; a failed operation or
	// closing proof ends the invocation as a failed per-operation proof did.
	for stage != 5 {
		if call.Err() != nil {
			return fail(cfg.ErrUnavailable)
		}
		b := &ownerBracket{root: root}
		inBracket = 0
		owned := func(ctx context.Context) context.Context {
			return context.WithValue(ctx, ownerProjectionControllerKey{}, s.projection)
		}
		bracket := fleetapp.Bracket{
			Now:     root.resources.now,
			Reserve: s.reserve,
			Open:    func(ctx context.Context) (time.Time, error) { return root.openOwnerBracket(owned(ctx), b) },
			Close:   func(ctx context.Context) error { return root.closeOwnerBracket(owned(ctx), b) },
		}
		_, err := bracket.Run(withOwnerBracket(call, b), step)
		root.endOwnerBracket(b)
		out.Brackets++
		if err != nil {
			return fail(err)
		}
	}
	out.Complete = true
	return out, nil
}

// ownerInstallationBracketReserve is the bracket lease that another
// operation needs: one role transition, or one projection or launch
// execution with its finalization, plus an unknown-result inspection.
const ownerInstallationBracketReserve = 2 * time.Second

func ownerInstallationProjectionRank(p *contracts.OwnerIdentityProjectionClaim) int {
	if p == nil {
		return 0
	}
	if p.Receipt != nil {
		return 6
	}
	if p.Configuration != nil {
		if p.Configuration.Receipt != nil {
			return 5
		}
		return 4
	}
	if p.Credentials != nil {
		if p.Credentials.Receipt != nil {
			return 3
		}
		return 2
	}
	return 1
}
