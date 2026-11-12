package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialBootstrapProviderClaim is private operation-owned state. Only the
// original acknowledged claim CAS grants Fresh. A retained pending claim never
// authorizes another provider POST, including after a process restart.
type InitialBootstrapProviderClaim struct {
	State      contracts.InitialBootstrapState
	Fresh      bool
	ValidUntil time.Time
}

func (InitialBootstrapProviderClaim) String() string {
	return "protected original bundled provider claim"
}
func (InitialBootstrapProviderClaim) GoString() string {
	return "protected original bundled provider claim"
}

func (s *InitialBootstrap) ClaimBundledProvider(ctx context.Context) (InitialBootstrapProviderClaim, error) {
	var zero InitialBootstrapProviderClaim
	bounded, end, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer end()
	if s.seedUID == "" {
		return zero, cfg.ErrInvalid
	}
	if err = s.current(bounded); err != nil {
		return zero, err
	}
	secret, state, err := s.readSeed(bounded)
	if err != nil {
		return zero, err
	}
	if state.Retired || state.Manager != nil || state.Material == nil || state.Material.BundledIdentity == nil {
		return zero, cfg.ErrChanged
	}
	fresh := false
	if state.ProviderMint == nil {
		if !bootstrapProviderPending(*state.Material) {
			return zero, cfg.ErrChanged
		}
		id, err := prepUUID()
		if err != nil {
			return zero, err
		}

		deadline, boundedDeadline := bounded.Deadline()
		if !boundedDeadline {
			return zero, cfg.ErrUnavailable
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		until := deadline.UTC().Truncate(time.Microsecond)
		if !at.Before(until) {
			return zero, cfg.ErrUnavailable
		}
		next := state
		next.ProviderMint = &contracts.InitialBootstrapProviderMint{OperationID: id, StartedAt: at, Until: until, ExpiresBefore: state.Material.BundledIdentity.SetupParent.ExpiresAt.Add(-contracts.BundledInitialProviderSafetyMargin)}
		if !next.ProviderMint.Until.Before(next.ProviderMint.ExpiresBefore) {
			return zero, cfg.ErrUnavailable
		}
		// An unknown or malformed response returns no Fresh authority. The
		// original claim, if committed, remains spent on every later read.
		if err = s.updateSeed(bounded, secret, state, next); err != nil {
			return zero, err
		}
		state = next
		fresh = true
	}
	if state.ProviderMint.Response == nil && !time.Now().Before(state.ProviderMint.Until) {
		return zero, cfg.ErrUnavailable
	}
	if err = s.current(bounded); err != nil {
		return zero, err
	}
	until, _ := bounded.Deadline()
	if state.ProviderMint.Response == nil && state.ProviderMint.Until.Before(until) {
		until = state.ProviderMint.Until
	}
	if s.probeUntil.Before(until) {
		until = s.probeUntil
	}
	return InitialBootstrapProviderClaim{State: state, Fresh: fresh, ValidUntil: until}, nil
}

// CompleteBundledProvider records one positively verified response and clears
// the setup credential in the SAME existing private seed CAS. A lost CAS reply
// may be resolved only by one exact original readback, never another mint.
func (s *InitialBootstrap) CompleteBundledProvider(ctx context.Context, claim InitialBootstrapProviderClaim, issuerToken string, parent contracts.InitialProviderParent) error {
	bounded, end, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer end()
	if claim.State.ProviderMint == nil || claim.State.Material == nil || !initialProviderASCII(issuerToken, contracts.InitialProviderTokenMaxBytes) || !time.Now().Before(claim.ValidUntil) || !time.Now().Before(parent.ExpiresAt) {
		return cfg.ErrInvalid
	}
	bounded, stop := context.WithDeadline(bounded, claim.ValidUntil)
	defer stop()
	if err = s.current(bounded); err != nil {
		return err
	}
	secret, state, err := s.readSeed(bounded)
	if err != nil {
		return err
	}
	if state.SeedUID != claim.State.SeedUID || state.ProviderMint == nil || state.Material == nil || state.Retired {
		return cfg.ErrChanged
	}
	if state.ProviderMint.Response != nil {
		if state.Material.IssuerToken != issuerToken || !equalJSON(state.ProviderMint.Response, parent) || !sameBootstrapMintIntent(*state.ProviderMint, *claim.State.ProviderMint) {
			return cfg.ErrChanged
		}
		return s.current(bounded)
	}
	if !claim.Fresh || !equalJSON(state, claim.State) || issuerToken == state.Material.SetupToken || parent.Accessor == state.Material.BundledIdentity.SetupParent.Accessor || !time.Now().Before(state.ProviderMint.Until) {
		return cfg.ErrChanged
	}
	next := state
	material := *state.Material
	material.SetupToken = ""
	material.IssuerToken = issuerToken
	next.Material = &material
	mint := *state.ProviderMint
	mint.Response = &parent
	next.ProviderMint = &mint
	if !bootstrapStateTransition(s.desired, state, next) {
		return cfg.ErrInvalid
	}
	if err = s.updateSeed(bounded, secret, state, next); err != nil {
		// Completion proof is a read of this exact same known result. Failure
		// or expiry is unavailable; neither creates a new request or deadline.
		observed, actual, readErr := s.readSeed(bounded)
		if readErr != nil || observed.UID != secret.UID || !equalJSON(actual, next) {
			return cfg.ErrUnavailable
		}
	}
	return s.current(bounded)
}
func sameBootstrapMintIntent(a, b contracts.InitialBootstrapProviderMint) bool {
	a.Response = nil
	b.Response = nil
	return equalJSON(a, b)
}
