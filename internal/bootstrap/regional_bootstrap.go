package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// regionalChannel is the one ADR-169 conversation the bootstrap opens.
type regionalChannel interface {
	Run(context.Context, func([]byte) (connectorlifecycle.Opening, error), connectorlifecycle.Local) (connectorlifecycle.HubFrame, error)
}

// errRegionalBootstrapExpired: the operator issues a new bootstrap and
// replaces the bootstrap record Secret (mode=combined: the hub does); this
// process never reuses an expired one and reseeds from a newer record.
var errRegionalBootstrapExpired = errors.New("cluster bootstrap expired")

// errRegionalBootstrapMissing: the cluster credential Secret is empty and no
// valid bootstrap record for this cluster binding is mounted.
var errRegionalBootstrapMissing = errors.New("cluster bootstrap record missing")

// regionalCredentialSeed writes the generation-0 envelope into the empty
// Helm-rendered cluster credential Secret.
type regionalCredentialSeed interface {
	SeedClusterCredential(context.Context, value.BootstrapEnvelope) error
}

// regionalRecord reads the operator's bootstrap record (bootstrap.json from
// the existing Secret named in values).
type regionalRecord interface {
	ReadBootstrapRecord(context.Context) (value.BootstrapEnvelope, error)
}

type regionalBootstrapRecord struct{ inputs *providerInputs }

func (r regionalBootstrapRecord) ReadBootstrapRecord(ctx context.Context) (value.BootstrapEnvelope, error) {
	b, err := r.inputs.read(ctx, contracts.ConnectorBootstrapFile, 16<<10)
	defer clear(b)
	if err != nil {
		return value.BootstrapEnvelope{}, errRegionalBootstrapMissing
	}
	return kms.DecodeBootstrapRecord(b)
}

// errRegionalCredentialWrite separates a refused Secret CAS write (RBAC,
// admission or a concurrent writer) from an unreadable Secret.
var errRegionalCredentialWrite = errors.New("cluster credential write refused")

// regionalBootstrap enrolls generation 1 in-band (ADR-193 step 3e). The
// pending key is CAS-written before any request, so a lost reply is resumed
// with the same key and the hub's replay; the envelope is erased only by the
// promotion to generation 1.
type regionalBootstrap struct {
	store   fleetapp.ClusterCredentialSecretStore
	seed    regionalCredentialSeed
	record  regionalRecord
	channel regionalChannel
	local   connectorlifecycle.Local
	binding value.PeerBinding
	root    string
	now     func() time.Time
}

// Reconcile returns nil once generation 1 or later is stored. An empty
// Secret is first seeded from the mounted bootstrap record of this exact
// binding; the record is never read again once the Secret holds a credential.
func (b regionalBootstrap) Reconcile(ctx context.Context) error {
	state, version, err := b.store.ReadClusterCredential(ctx)
	if errors.Is(err, kube.ErrClusterCredentialEmpty) {
		envelope, rerr := b.record.ReadBootstrapRecord(ctx)
		if rerr != nil || envelope.Binding != b.binding {
			return errRegionalBootstrapMissing
		}
		if !b.now().Before(envelope.NotAfter) {
			return errRegionalBootstrapExpired
		}
		if err = b.seed.SeedClusterCredential(ctx, envelope); err != nil {
			return errors.Join(err, errRegionalCredentialWrite)
		}
		state, version, err = b.store.ReadClusterCredential(ctx)
	}
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
		// mode=combined: the hub replaces a slot that expired unclaimed with
		// a new record for the same binding. The expired slot was never
		// claimed, so its pending key is discarded with it.
		next, rerr := b.record.ReadBootstrapRecord(ctx)
		if rerr != nil || next.Binding != b.binding || next.BootstrapID == e.BootstrapID || !b.now().Before(next.NotAfter) {
			return errRegionalBootstrapExpired
		}
		clear(state.PendingSeed)
		state = fleetapp.ClusterCredentialSecret{Bootstrap: &next}
		if version, err = b.store.WriteClusterCredential(ctx, version, state); err != nil {
			return errors.Join(err, errRegionalCredentialWrite)
		}
		e = next
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
