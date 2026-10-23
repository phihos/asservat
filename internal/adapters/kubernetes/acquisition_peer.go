package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// DispatchedAcquisitionPeerAttester consumes the stored, exact admitted parent
// and Pod. It shares the native worker's actual TokenReview/object proof and
// protected source checks; a query ID never supplies a download authority.
type DispatchedAcquisitionPeerAttester struct {
	client   *PermissionClient
	bindings app.AcquisitionEnrollmentBindings
	tokens   app.DownloadPeerToken
}

func NewDispatchedAcquisitionPeerAttester(c *PermissionClient, bindings app.AcquisitionEnrollmentBindings, token app.DownloadPeerToken) (*DispatchedAcquisitionPeerAttester, error) {
	if c == nil || bindings == nil || token == nil {
		return nil, artifact.ErrInvalid
	}
	return &DispatchedAcquisitionPeerAttester{c, bindings, token}, nil
}

func (s *DispatchedAcquisitionPeerAttester) ReadAcquisitionPeerProof(ctx context.Context, parent value.AcquisitionParent, worker string, peer value.KeyPeer) (value.AcquisitionPeerProof, error) {
	var zero value.AcquisitionPeerProof
	if s == nil || ctx == nil || ctx.Err() != nil || !parent.Valid() || !value.UUID(worker) {
		return zero, artifact.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	start := s.client.now()
	observed, err := s.bindings.ReadAcquisitionEnrollment(call, parent, worker)
	w := observed.Worker
	if err != nil || !observed.Valid(s.client.now()) || w.Intent.ID != worker || w.Intent.Parent != parent || w.Binding.PodUID != peer.PeerID || peer.InstallationID != w.Binding.InstallationID {
		return zero, artifact.ErrInvalid
	}
	p := w.Intent.Profile
	if s.client.clusterID != p.ClusterID || s.client.control.Name != p.Namespace || s.client.control.UID != p.NamespaceUID {
		return zero, artifact.ErrInvalid
	}
	bounded, end := context.WithDeadline(call, observed.FreshUntil)
	defer end()
	jobs := &DownloadWorkerJobs{client: s.client, profile: p}
	if jobs.sources(bounded) != nil {
		return zero, artifact.ErrInvalid
	}
	attester, err := NewAcquisitionPeerAttester(s.client, w.Binding, s.tokens)
	if err != nil {
		return zero, err
	}
	proof, err := attester.ReadAcquisitionPeerProof(bounded, parent, peer)
	if err != nil {
		return zero, err
	}
	if jobs.sources(bounded) != nil || s.client.current(bounded, start, 5*time.Second) != nil {
		return zero, artifact.ErrInvalid
	}
	proof.ObservedAt = start
	proof.FreshUntil = identity.Earlier(proof.FreshUntil, identity.Earlier(observed.FreshUntil, identity.Earlier(start.Add(5*time.Second), w.Intent.RunUntil)))
	if !proof.Valid(s.client.now()) || bounded.Err() != nil {
		return zero, artifact.ErrInvalid
	}
	return proof, nil
}

var _ app.AcquisitionPeerProofReader = (*DispatchedAcquisitionPeerAttester)(nil)
