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
