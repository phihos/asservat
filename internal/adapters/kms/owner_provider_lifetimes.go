package kms

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Four fixed compartments, not a provider/purpose registry. No runtime input
// currently selects this constructor; installed v2 composition must pin the
// original profile, projected JWT, concrete current-proof and process ceiling.
type ownerProviderLifetimes struct {
	auditWrap, auditUnwrap, serverSign, clientSign *ownerProviderLifetime
	// public holds the ADR-182 public purposes in providerconfig order; all
	// nil without a pinned public recipe.
	public [4]*ownerProviderLifetime
	// fleet is the ADR-193 bootstrap credential channel; nil without Fleet.
	fleet  *ownerProviderLifetime
	cancel context.CancelFunc
}

// all returns every compartment, identity first.
func (s *ownerProviderLifetimes) all() []*ownerProviderLifetime {
	out := []*ownerProviderLifetime{s.auditWrap, s.auditUnwrap, s.serverSign, s.clientSign}
	for _, slot := range s.public {
		if slot != nil {
			out = append(out, slot)
		}
	}
	if s.fleet != nil {
		out = append(out, s.fleet)
	}
	return out
}

func newOwnerProviderLifetimes(ctx context.Context, input contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, jwt TokenSource, proof ownerProviderCurrent, client *http.Client, concurrency int, now func() time.Time) (*ownerProviderLifetimes, error) {
	if ctx == nil || ctx.Err() != nil || concurrency < 1 || concurrency > 16 || proof == nil || jwt == nil || now == nil {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	out := &ownerProviderLifetimes{cancel: cancel}
	fixed := []struct {
		purpose string
		target  **ownerProviderLifetime
	}{
		{"audit-wrap", &out.auditWrap}, {"audit-unwrap", &out.auditUnwrap}, {"server-sign", &out.serverSign}, {"client-sign", &out.clientSign},
	}
	if input.Public != nil && input.Public.ProviderRecipeSHA256 != "" {
		for i, purpose := range providerconfig.OwnerPublicProviderPurposes {
			fixed = append(fixed, struct {
				purpose string
				target  **ownerProviderLifetime
			}{purpose, &out.public[i]})
		}
	}
	if input.Public != nil && input.Public.Fleet != nil {
		fixed = append(fixed, struct {
			purpose string
			target  **ownerProviderLifetime
		}{providerconfig.OwnerFleetProviderPurpose, &out.fleet})
	}
	for _, fixed := range fixed {
		control, err := newOwnerProviderControl(input, profile, fixed.purpose, client, now)
		if err != nil {
			cancel()
			out.close(context.Background())
			return nil, err
		}
		slot, err := newOwnerProviderLifetime(root, control, jwt, proof, concurrency)
		if err != nil {
			control.close()
			cancel()
			out.close(context.Background())
			return nil, err
		}
		*fixed.target = slot
	}
	return out, nil
}

func (s *ownerProviderLifetimes) close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.cancel() // cancel every purpose before waiting for any one close
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	var result error
	for _, slot := range s.all() {
		if slot != nil {
			if err := slot.close(call); err != nil {
				result = ErrKeyService
			}
		}
	}
	return result
}

// joinClosed preserves every original operation's deadline while retaining
// ownership until all four cancelled compartments have positively joined.
func (s *ownerProviderLifetimes) joinClosed() {
	if s == nil {
		return
	}
	s.cancel()
	for _, slot := range s.all() {
		if slot != nil {
			slot.joinClosed()
		}
	}
}
