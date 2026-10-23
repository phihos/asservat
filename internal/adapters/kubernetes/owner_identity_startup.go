package kubernetes

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// This is a passive installation state, never a current identity proof. Only
// journal() creates it after checking the complete original journal shape and
// pins. Its private public-state value contains no credential material.
type ownerLaunchReceiptPending struct {
	state contracts.InitialRuntimeResourceState
}

func (*ownerLaunchReceiptPending) Error() string { return "original owner launch receipt pending" }
func (*ownerLaunchReceiptPending) Unwrap() error { return cfg.ErrUnavailable }

// Compare the entire first pending public state. Only the original launch's
// receipt may appear; even valid unrelated journal progress cannot be adopted.
func ownerLaunchReceiptTransition(original, current contracts.InitialRuntimeResourceState) bool {
	if original.OwnerLaunch == nil || original.OwnerLaunch.Receipt != nil || current.OwnerLaunch == nil {
		return false
	}
	launch := *current.OwnerLaunch
	launch.Receipt = nil
	current.OwnerLaunch = &launch
	return equalJSON(original, current)
}

// VerifyStartup permits passive convergence of one original launch receipt
// within the caller's existing startup deadline (at most thirty seconds). It
// never renews a launch/effect attempt or uses SQL/provider credentials while
// pending. Runtime Verify remains one bounded proof with no convergence loop.
func (s *InstalledOwnerIdentityReader) VerifyStartup(ctx context.Context, manifest contracts.OwnerIdentityCredentialManifest, mounted map[string][]byte) (time.Time, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return time.Time{}, cfg.ErrInvalid
	}
	startup, cancel := context.WithDeadline(ctx, s.client.now().Add(30*time.Second))
	defer cancel()
	until, err := s.Verify(startup, manifest, mounted)
	var pending *ownerLaunchReceiptPending
	// A completed journal that loses its receipt during Verify is Changed;
	// it must never be reclassified as a newly pending installation.
	if !errors.As(err, &pending) || errors.Is(err, cfg.ErrChanged) || errors.Is(err, cfg.ErrDenied) || errors.Is(err, cfg.ErrInvalid) {
		return until, err
	}
	until, err = awaitOwnerLaunchReceipt(startup, pending.state, s.client.now, s.journal,
		func(call context.Context, completed contracts.InitialRuntimeResourceState) (time.Time, error) {
			return s.verify(call, manifest, mounted, &completed)
		})
	if err != nil {
		return time.Time{}, err
	}
	return callerBound(ctx, until), nil
}

// read is only the exact original journal GET; verify is the full native
// guard/token/object/Pod/journal bracket. The separate arguments make explicit
// that passive observations cannot yield authority, even after a receipt.
func awaitOwnerLaunchReceipt(ctx context.Context, original contracts.InitialRuntimeResourceState, now func() time.Time,
	read func(context.Context) (contracts.InitialRuntimeResourceState, error), verify func(context.Context, contracts.InitialRuntimeResourceState) (time.Time, error)) (time.Time, error) {
	if ctx == nil || now == nil || read == nil || verify == nil || original.OwnerLaunch == nil || original.OwnerLaunch.Receipt != nil {
		return time.Time{}, cfg.ErrInvalid
	}
	parentEnd, ok := ctx.Deadline()
	if !ok {
		return time.Time{}, cfg.ErrInvalid
	}
	end := identity.Earlier(parentEnd, original.Until)
	bounded, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	for {
		if err := initialHandoverDeadline(bounded, now, end); err != nil {
			return time.Time{}, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return time.Time{}, errors.Join(cfg.ErrUnavailable, bounded.Err())
		case <-timer.C:
		}
		call, stop := context.WithDeadline(bounded, identity.Earlier(end, now().Add(5*time.Second)))
		current, err := read(call)
		callEnd, _ := call.Deadline()
		deadlineErr := initialHandoverDeadline(call, now, callEnd)
		stop()
		if deadlineErr != nil {
			return time.Time{}, deadlineErr
		}
		var pending *ownerLaunchReceiptPending
		if errors.As(err, &pending) {
			current = pending.state
		} else if err != nil {
			return time.Time{}, err
		}
		if !ownerLaunchReceiptTransition(original, current) {
			return time.Time{}, cfg.ErrChanged
		}
		if pending != nil {
			continue
		}
		if current.OwnerLaunch.Receipt == nil {
			return time.Time{}, cfg.ErrChanged
		}
		// A fresh full proof is mandatory after convergence, retaining the
		// first positive receipt, entire completed state and unchanged startup
		// deadline. A different receipt cannot be selected during that proof.
		until, err := verify(bounded, current)
		if err != nil {
			return time.Time{}, err
		}
		if err = initialHandoverDeadline(bounded, now, identity.Earlier(until, end)); err != nil {
			return time.Time{}, err
		}
		return until, nil
	}
}
