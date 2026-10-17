package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ClusterCredentialSecret is the connector's protected Secret content. Seeds
// are Ed25519 private key seeds; they never leave the workload cluster.
//
// ADR-193: generation 0 holds only the operator's bootstrap envelope and,
// once written before any request, the pending generation-1 seed. Activation
// replaces it with generation 1 and erases the envelope.
type ClusterCredentialSecret struct {
	Generation  int64
	Seed        []byte                   `json:",omitempty"`
	PendingSeed []byte                   `json:",omitempty"`
	RotatedAt   time.Time                `json:",omitempty"`
	Bootstrap   *value.BootstrapEnvelope `json:",omitempty"`
}

func (s ClusterCredentialSecret) Valid() bool {
	pending := s.PendingSeed == nil || len(s.PendingSeed) == ed25519.SeedSize
	if s.Generation == 0 {
		return s.Bootstrap != nil && s.Bootstrap.Valid() && s.Seed == nil && pending
	}
	return s.Generation >= 1 && s.Bootstrap == nil && len(s.Seed) == ed25519.SeedSize && pending && !s.RotatedAt.IsZero()
}

// ClusterCredentialSecretStore reads and compare-and-swaps exactly one named
// Secret. Version is the opaque resourceVersion of the read.
type ClusterCredentialSecretStore interface {
	ReadClusterCredential(context.Context) (ClusterCredentialSecret, string, error)
	WriteClusterCredential(context.Context, string, ClusterCredentialSecret) (string, error)
}

// ClusterCredentialExchanger performs one exporter-bound exchange with the hub
// and returns the accepted generation.
type ClusterCredentialExchanger interface {
	ExchangeClusterCredential(context.Context, value.ClusterCredentialRequest, func(exporter []byte) ([]byte, error)) (int64, error)
}

type ClusterCredentialRotator struct {
	Profile  value.ClusterCredentialProfile
	Policy   value.ClusterCredentialPolicy
	Store    ClusterCredentialSecretStore
	Exchange ClusterCredentialExchanger
	Now      func() time.Time
}

func (r ClusterCredentialRotator) valid() bool {
	return r.Profile.Valid() && r.Policy.Valid() && r.Store != nil && r.Exchange != nil && r.Now != nil
}

// Reconcile completes a pending rotation or starts one when due. The pending
// key is persisted before any request, so an uncertain reply or a crash can
// only be followed by the exact same rotation, never a second pending key.
// ErrClusterCredentialFenced is permanent and must stop the supervisor.
func (r ClusterCredentialRotator) Reconcile(ctx context.Context) error {
	if !r.valid() || ctx == nil {
		return value.ErrClusterCredentialDenied
	}
	state, version, err := r.Store.ReadClusterCredential(ctx)
	if err != nil {
		return err
	}
	if !state.Valid() {
		return value.ErrClusterCredentialDenied
	}
	if state.Generation == 0 {
		return value.ErrClusterBootstrapPending // only the bootstrap enrolls
	}
	if state.PendingSeed == nil {
		if r.Now().Before(state.RotatedAt.Add(r.Policy.Rotation)) {
			return nil
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return err
		}
		state.PendingSeed = seed
		if version, err = r.Store.WriteClusterCredential(ctx, version, state); err != nil {
			return err
		}
	}
	current := ed25519.NewKeyFromSeed(state.Seed)
	next := ed25519.NewKeyFromSeed(state.PendingSeed).Public().(ed25519.PublicKey)
	request := value.ClusterCredentialRequest{Operation: value.ClusterRotation, Profile: r.Profile, Generation: state.Generation, NextKey: next, RequestedAt: r.Now().UTC().Truncate(time.Microsecond)}
	generation, err := r.Exchange.ExchangeClusterCredential(ctx, request, func(exporter []byte) ([]byte, error) {
		return SignClusterCredentialRequest(current, request, exporter)
	})
	if err != nil {
		return err // pending stays; only this exact rotation may be repeated
	}
	if generation != state.Generation+1 {
		return errors.New("cluster enrollment rotation returned an unexpected generation")
	}
	_, err = r.Store.WriteClusterCredential(ctx, version, ClusterCredentialSecret{Generation: generation, Seed: state.PendingSeed, RotatedAt: r.Now().UTC().Truncate(time.Microsecond)})
	return err
}

// Signer completes an admission or renewal request with the current
// generation and returns its exporter-bound signer. It refuses while a rotation
// is pending, because the hub treats the old key as superseded once the
// rotation committed.
func (r ClusterCredentialRotator) Signer(ctx context.Context, request value.ClusterCredentialRequest) (value.ClusterCredentialRequest, func(exporter []byte) ([]byte, error), error) {
	if !r.valid() || ctx == nil || request.Operation == value.ClusterRotation {
		return request, nil, value.ErrClusterCredentialDenied
	}
	state, _, err := r.Store.ReadClusterCredential(ctx)
	if err != nil || !state.Valid() || state.PendingSeed != nil {
		return request, nil, value.ErrClusterCredentialDenied
	}
	if state.Generation == 0 {
		return request, nil, value.ErrClusterBootstrapPending
	}
	request.Generation, request.Profile = state.Generation, r.Profile
	if !request.Valid() {
		return request, nil, value.ErrClusterCredentialDenied
	}
	key := ed25519.NewKeyFromSeed(state.Seed)
	return request, func(exporter []byte) ([]byte, error) { return SignClusterCredentialRequest(key, request, exporter) }, nil
}
