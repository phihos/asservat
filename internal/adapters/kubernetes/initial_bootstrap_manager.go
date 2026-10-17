package kubernetes

import (
	"context"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialBootstrapManagerClaim is a process-owned current observation. Fresh
// is true only after this call's acknowledged original private-state CAS. A
// replay returns the same intent with Fresh=false and is lookup-only in SQL.
type InitialBootstrapManagerClaim struct {
	State      contracts.InitialBootstrapState
	Fresh      bool
	ValidUntil time.Time
}

func (InitialBootstrapManagerClaim) String() string   { return "protected original SQL manager claim" }
func (InitialBootstrapManagerClaim) GoString() string { return "protected original SQL manager claim" }

// These purpose-specific methods are the SQL producer's direct protected
// journal port. Production composition supplies this concrete adapter; no
// transport accepts state, Fresh or private passwords from a caller.
func (s *InitialBootstrap) ClaimBootstrapSQLManager(ctx context.Context, oid uint32, started time.Time) (contracts.InitialBootstrapState, bool, time.Time, error) {
	v, e := s.ClaimManager(ctx, oid, started)
	return v.State, v.Fresh, v.ValidUntil, e
}
func (s *InitialBootstrap) CompleteBootstrapSQLManager(ctx context.Context, state contracts.InitialBootstrapState, until time.Time, receipt contracts.InitialSQLHistoryManager) error {
	return s.CompleteManager(ctx, InitialBootstrapManagerClaim{State: state, ValidUntil: until}, receipt)
}
func (s *InitialBootstrap) ReadBootstrapSQLManager(ctx context.Context) (contracts.InitialBootstrapState, time.Time, error) {
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, e
	}
	defer end()
	if s.seedUID == "" {
		return contracts.InitialBootstrapState{}, time.Time{}, cfg.ErrInvalid
	}
	if e = s.current(bounded); e != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, e
	}
	_, state, e := s.readSeed(bounded)
	if e != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, e
	}
	if e = s.current(bounded); e != nil {
		return contracts.InitialBootstrapState{}, time.Time{}, e
	}
	until, _ := bounded.Deadline()
	if s.probeUntil.Before(until) {
		until = s.probeUntil
	}
	return state, until, nil
}

func (s *InitialBootstrap) ClaimManager(ctx context.Context, databaseOID uint32, postmasterAt time.Time) (InitialBootstrapManagerClaim, error) {
	var zero InitialBootstrapManagerClaim
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer end()
	if s.seedUID == "" || databaseOID == 0 || postmasterAt.Year() < 2020 || !postmasterAt.Equal(postmasterAt.Truncate(time.Microsecond)) {
		return zero, cfg.ErrInvalid
	}
	if e = s.current(bounded); e != nil {
		return zero, e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil {
		return zero, e
	}
	if state.Retired {
		return zero, cfg.ErrChanged
	}
	fresh := false
	if state.Manager == nil {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		started := time.Now().UTC().Truncate(time.Microsecond)
		next := state
		next.Manager = &contracts.InitialBootstrapManager{OperationID: id, StartedAt: started, Until: started.Add(30 * time.Minute), DatabaseOID: databaseOID, PostmasterAt: postmasterAt.UTC()}
		if e = s.updateSeed(bounded, secret, state, next); e != nil {
			return zero, e
		}
		state = next
		fresh = true
	}
	if state.Manager.DatabaseOID != databaseOID || !state.Manager.PostmasterAt.Equal(postmasterAt) || state.Manager.Closing != nil || !time.Now().Before(state.Manager.Until) {
		return zero, cfg.ErrChanged
	}
	if e = s.current(bounded); e != nil {
		return zero, e
	}
	until, _ := bounded.Deadline()
	if state.Manager.Until.Before(until) {
		until = state.Manager.Until
	}
	if s.probeUntil.Before(until) {
		until = s.probeUntil
	}
	return InitialBootstrapManagerClaim{State: state, Fresh: fresh, ValidUntil: until}, nil
}

func (s *InitialBootstrap) CompleteManager(ctx context.Context, claim InitialBootstrapManagerClaim, receipt contracts.InitialSQLHistoryManager) error {
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return e
	}
	defer end()
	if claim.State.Manager == nil || !time.Now().Before(claim.ValidUntil) || receipt.OID == 0 || receipt.OID == 10 || receipt.Name != "asservat_init_"+strings.ReplaceAll(claim.State.InstallationID, "-", "")+"_manager" {
		return cfg.ErrInvalid
	}
	bounded, stop := context.WithDeadline(bounded, claim.ValidUntil)
	defer stop()
	if e = s.current(bounded); e != nil {
		return e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil {
		return e
	}
	if state.Manager == nil || state.Manager.Closing != nil || state.SeedUID != claim.State.SeedUID || state.Manager.OperationID != claim.State.Manager.OperationID || state.Manager.DatabaseOID != claim.State.Manager.DatabaseOID || !state.Manager.PostmasterAt.Equal(claim.State.Manager.PostmasterAt) || !state.Manager.StartedAt.Equal(claim.State.Manager.StartedAt) || !state.Manager.Until.Equal(claim.State.Manager.Until) {
		return cfg.ErrChanged
	}
	if state.Manager.Receipt != nil {
		if *state.Manager.Receipt != receipt {
			return cfg.ErrChanged
		}
		return s.current(bounded)
	}
	next := state
	m := *state.Manager
	next.Manager = &m
	m.Receipt = &receipt
	return s.updateSeed(bounded, secret, state, next)
}

// BeginManagerClose is a restrictive, irreversible fence. The supervisor calls
// it after completed handover (also checked here), then joins its owned
// preparation pool before asking the separate SQL administrator to retire the
// login. This journal value alone is never proof of handover or SQL closure.
func (s *InitialBootstrap) BeginManagerClose(ctx context.Context) (InitialBootstrapManagerClaim, error) {
	var zero InitialBootstrapManagerClaim
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer end()
	if s.seedUID == "" {
		return zero, cfg.ErrInvalid
	}
	if e = s.current(bounded); e != nil {
		return zero, e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil {
		return zero, e
	}
	if state.Manager == nil || state.Manager.Receipt == nil || state.Projection == nil {
		return zero, cfg.ErrChanged
	}
	projection, ready, e := s.readProjection(bounded, state)
	if e != nil || !ready {
		return zero, cfg.ErrUnavailable
	}
	preparer, e := NewInitialPreparer(s.config, s.proof.observer, s.proof.probe, projection)
	if e != nil {
		return zero, e
	}
	defer preparer.Close()
	handover, passive, e := preparer.ReadHandover(bounded)
	if e != nil || !passive || !preparer.HandoverCleanupComplete(handover) || bounded.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	fresh := false
	if state.Manager.Closing == nil {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		next := state
		m := *state.Manager
		next.Manager = &m
		m.Closing = &contracts.InitialBootstrapClose{OperationID: id, StartedAt: now, Until: now.Add(30 * time.Second)}
		if e = s.updateSeed(bounded, secret, state, next); e != nil {
			return zero, e
		}
		state, fresh = next, true
	}
	if e = s.current(bounded); e != nil {
		return zero, e
	}
	until, _ := bounded.Deadline()
	if s.probeUntil.Before(until) {
		until = s.probeUntil
	}
	// An expired closing intent remains readable for exact-state reconciliation;
	// the SQL effect facet independently enforces its original closing interval.
	return InitialBootstrapManagerClaim{State: state, Fresh: fresh, ValidUntil: until}, nil
}

// CompleteManagerClose retains a positively observed original SQL completion.
// Unknown SQL outcomes cannot manufacture this receipt from elapsed time.
func (s *InitialBootstrap) CompleteManagerClose(ctx context.Context, claim InitialBootstrapManagerClaim, retiredAt time.Time) error {
	bounded, end, e := s.enter(ctx)
	if e != nil {
		return e
	}
	defer end()
	if claim.State.Manager == nil || claim.State.Manager.Closing == nil || !time.Now().Before(claim.ValidUntil) {
		return cfg.ErrInvalid
	}
	bounded, stop := context.WithDeadline(bounded, claim.ValidUntil)
	defer stop()
	if e = s.current(bounded); e != nil {
		return e
	}
	secret, state, e := s.readSeed(bounded)
	if e != nil {
		return e
	}
	if state.Manager == nil || state.SeedUID != claim.State.SeedUID || !equalJSON(state.Manager.Closing, claim.State.Manager.Closing) || !equalJSON(state.Manager.Receipt, claim.State.Manager.Receipt) || state.Manager.OperationID != claim.State.Manager.OperationID {
		return cfg.ErrChanged
	}
	if state.Manager.RetiredAt != nil {
		if !state.Manager.RetiredAt.Equal(retiredAt) {
			return cfg.ErrChanged
		}
		return s.current(bounded)
	}
	next := state
	m := *state.Manager
	next.Manager = &m
	m.RetiredAt = &retiredAt
	return s.updateSeed(bounded, secret, state, next)
}
