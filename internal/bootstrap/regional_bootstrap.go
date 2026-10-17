package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// regionalChannel is the one ADR-169 conversation the bootstrap opens.
type regionalChannel interface {
	Run(context.Context, func([]byte) (connectorlifecycle.Opening, error), connectorlifecycle.Local) (connectorlifecycle.HubFrame, error)
}

// errRegionalBootstrapExpired: the operator issues a new bootstrap and the
// installer rewrites the Secret; this process never reuses an expired one.
var errRegionalBootstrapExpired = errors.New("cluster bootstrap expired")

// errRegionalCredentialWrite separates a refused Secret CAS write (RBAC,
// admission or a concurrent writer) from an unreadable Secret.
var errRegionalCredentialWrite = errors.New("cluster credential write refused")

// regionalBootstrap enrolls generation 1 in-band (ADR-193 step 3e). The
// pending key is CAS-written before any request, so a lost reply is resumed
// with the same key and the hub's replay; the envelope is erased only by the
// promotion to generation 1.
type regionalBootstrap struct {
	store   fleetapp.ClusterCredentialSecretStore
	channel regionalChannel
	local   connectorlifecycle.Local
	binding value.PeerBinding
	root    string
	now     func() time.Time
}

// Reconcile returns nil once generation 1 or later is stored.
func (b regionalBootstrap) Reconcile(ctx context.Context) error {
	state, version, err := b.store.ReadClusterCredential(ctx)
	if err != nil {
		return errors.Join(err, errRegionalCredential)
	}
	if state.Generation >= 1 {
		return nil
	}
	e := *state.Bootstrap
	if e.Binding != b.binding {
		return value.ErrDenied // the regional source names another slot
	}
	if !b.now().Before(e.NotAfter) {
		return errRegionalBootstrapExpired
	}
	if state.PendingSeed == nil {
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return errRegionalCredential
		}
		state.PendingSeed = seed
		if version, err = b.store.WriteClusterCredential(ctx, version, state); err != nil {
			return errors.Join(err, errRegionalCredentialWrite)
		}
	}
	defer clear(state.PendingSeed)
	key := ed25519.NewKeyFromSeed(state.PendingSeed)
	defer clear(key)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return errRegionalCredential
	}
	secret, err := mtls.BootstrapDigest(e.Binding.InstallationID, e.BootstrapID, e.Secret)
	if err != nil {
		return value.ErrInvalid
	}
	r := value.ClusterBootstrapRequest{InstallationID: e.Binding.InstallationID, BootstrapID: e.BootstrapID, RootID: b.root, ClusterID: e.Binding.ClusterID, PeerID: e.Binding.PeerID, IssuerEpoch: e.Binding.IssuerEpoch,
		KeyDigest: fleetapp.ClusterBootstrapKeyDigest(key.Public().(ed25519.PublicKey)), SecretDigest: secret, RequestedAt: b.now().UTC().Truncate(time.Microsecond)}
	frame, err := b.channel.Run(ctx, func(exporter []byte) (connectorlifecycle.Opening, error) {
		signature, err := fleetapp.SignClusterBootstrapRequest(key, r, exporter)
		return connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeBootstrap, Bootstrap: &connectorlifecycle.BootstrapOpening{Secret: e.Secret, CSRDER: csr, Request: r, Signature: signature}}, err
	}, b.local)
	switch {
	case err != nil:
		return errRegionalChannel
	case frame.Kind == "failure" && frame.Failure == "fenced":
		return value.ErrClusterCredentialFenced
	case frame.Kind != "result" || frame.Bootstrap == nil || !frame.Bootstrap.Valid() || frame.Bootstrap.KeyDigest != r.KeyDigest:
		return errRegionalRefused
	}
	_, err = b.store.WriteClusterCredential(ctx, version, fleetapp.ClusterCredentialSecret{Generation: 1, Seed: state.PendingSeed, RotatedAt: b.now().UTC().Truncate(time.Microsecond)})
	if err != nil {
		return errors.Join(err, errRegionalCredentialWrite)
	}
	return nil
}
