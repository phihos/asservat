package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"errors"
	"time"
)

type NativeLocator interface {
	LocateNativeOperation(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error)
}
type NativeProofFactory func(DownloadPeerToken) (DownloadPeerProofReader, error)
type ProjectionNativeReader interface {
	AcquisitionEnrollmentBindings
	ReadProjectionWorkerCertificate(context.Context, string, string, []byte) (value.WorkerCertificate, error)
	LocateProjectionNativeOperation(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error)
	ObserveProjectionNativeOperation(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error)
}
type AcquisitionPeerProofReader interface {
	ReadAcquisitionPeerProof(context.Context, value.AcquisitionParent, string, value.KeyPeer) (value.AcquisitionPeerProof, error)
}
type ProjectionNativeProofFactory func(DownloadPeerToken) (AcquisitionPeerProofReader, error)

// NativeOrigin is the current private worker origin, never human authority.
// Connector TLS supplies Peer; the hub separately authenticates the connector
// before using its exact leaf observation and repeating this Pod/SQL check.
type NativeOrigin struct {
	Lease value.NativeLease
	Proof value.AcquisitionPeerProof
}
type NativeOrigins struct {
	Locators         NativeLocator
	Operations       NativeOperationReader
	Proofs           NativeProofFactory
	Now              func() time.Time
	Projection       ProjectionNativeReader
	ProjectionProofs ProjectionNativeProofFactory
}

func (s NativeOrigins) Check(ctx context.Context, installation, session, worker string, peer value.KeyPeer, token []byte) (NativeOrigin, error) {
	return s.CheckAcquisition(ctx, installation, value.AcquisitionParent{Purpose: value.AcquisitionDownload, ID: session}, worker, peer, token)
}
func (s NativeOrigins) CheckAcquisition(ctx context.Context, installation string, parent value.AcquisitionParent, worker string, peer value.KeyPeer, token []byte) (NativeOrigin, error) {
	var zero NativeOrigin
	if ctx == nil || ctx.Err() != nil || !parent.Valid() || s.Now == nil || len(token) < 1 || len(token) > 16<<10 || !peer.Valid(s.Now()) || peer.Role != "acquisition" || peer.InstallationID != installation {
		return zero, artifact.ErrInvalid
	}
	start := s.Now()
	call, stop := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer stop()
	owned := enrollmentToken(bytes.Clone(token))
	defer clear(owned)
	var p value.AcquisitionPeerProof
	var l value.NativeLease
	var e error
	switch parent.Purpose {
	case value.AcquisitionDownload:
		if s.Proofs == nil || s.Locators == nil || s.Operations == nil {
			return zero, artifact.ErrInvalid
		}
		proofs, err := s.Proofs(owned)
		if err != nil || proofs == nil {
			return zero, artifact.ErrDownloadUnavailable
		}
		original, err := proofs.ReadDownloadPeerProof(call, parent.ID, peer)
		if err != nil || !original.Valid(s.Now()) {
			return zero, artifact.ErrDownloadUnavailable
		}
		p = original.Acquisition()
		if p.Peer != peer || p.Binding.Parent != parent || p.Binding.InstallationID != installation {
			return zero, artifact.ErrDownloadUnavailable
		}
		l, e = s.Locators.LocateNativeOperation(call, installation, parent.ID, worker, peer)
	case value.AcquisitionProjection:
		if s.ProjectionProofs == nil || s.Projection == nil {
			return zero, artifact.ErrInvalid
		}
		proofs, err := s.ProjectionProofs(owned)
		if err != nil || proofs == nil {
			return zero, artifact.ErrDownloadUnavailable
		}
		p, err = proofs.ReadAcquisitionPeerProof(call, parent, worker, peer)
		if err != nil || !p.Valid(s.Now()) || p.Peer != peer || p.Binding.Parent != parent || p.Binding.InstallationID != installation {
			return zero, artifact.ErrDownloadUnavailable
		}
		l, e = s.Projection.LocateProjectionNativeOperation(call, installation, parent.ID, worker, peer)
	default:
		return zero, artifact.ErrInvalid
	}
	var absent *NativeNoOperation
	if errors.As(e, &absent) && absent != nil {
		idle := &NativeIdle{Worker: absent.Worker, Proof: p, ObservedAt: start, Until: identity.Earlier(p.FreshUntil, absent.Worker.FreshUntil)}
		idle.Until = identity.Earlier(idle.Until, start.Add(5*time.Second))
		if d, ok := call.Deadline(); ok {
			idle.Until = identity.Earlier(idle.Until, d)
		}
		if idle.Valid(s.Now()) && absent.Worker.Worker.Intent.ID == worker && call.Err() == nil {
			return zero, idle
		}
		return zero, artifact.ErrDownloadUnavailable
	}
	if e != nil || !l.Valid(s.Now()) || l.Operation.WorkerPodUID != p.Binding.PodUID || l.Operation.Reference.WorkerID != worker {
		return zero, artifact.ErrDownloadUnavailable
	}
	l.Until = identity.Earlier(l.Until, identity.Earlier(p.FreshUntil, start.Add(5*time.Second)))
	if d, ok := call.Deadline(); ok {
		l.Until = identity.Earlier(l.Until, d)
	}
	if !l.Valid(s.Now()) || !p.Valid(s.Now()) || call.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	return NativeOrigin{l, p}, nil
}

// Recheck reuses only the still-current original Pod proof. The SQL/current-peer
// observation may shorten but never replace its operation or extend its expiry.
func (s NativeOrigins) Recheck(ctx context.Context, original NativeOrigin) (value.NativeLease, error) {
	if ctx == nil || s.Now == nil || !original.Lease.Valid(s.Now()) || !original.Proof.Valid(s.Now()) {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	call, stop := context.WithDeadline(ctx, original.Lease.Until)
	defer stop()
	var l value.NativeLease
	var e error
	ref := original.Lease.Operation.Reference
	switch ref.Parent().Purpose {
	case value.AcquisitionDownload:
		if s.Operations == nil {
			return value.NativeLease{}, artifact.ErrInvalid
		}
		l, e = s.Operations.ObserveNativeOperation(call, ref, original.Proof.Peer)
	case value.AcquisitionProjection:
		if s.Projection == nil {
			return value.NativeLease{}, artifact.ErrInvalid
		}
		l, e = s.Projection.ObserveProjectionNativeOperation(call, ref, original.Proof.Peer)
	default:
		return value.NativeLease{}, artifact.ErrInvalid
	}
	if e != nil || !sameNativeOperation(l.Operation, original.Lease.Operation) || l.Sequence != original.Lease.Sequence || l.Certificate != original.Lease.Certificate {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	l.Until = identity.Earlier(l.Until, original.Lease.Until)
	if !l.Valid(s.Now()) || !original.Proof.Valid(s.Now()) || call.Err() != nil {
		return value.NativeLease{}, artifact.ErrDownloadExpired
	}
	return l, nil
}
