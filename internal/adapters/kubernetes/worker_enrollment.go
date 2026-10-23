package kubernetes

import (
	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

type WorkerEnrollmentAttester struct {
	client   *PermissionClient
	bindings app.WorkerEnrollmentBindings
	tokens   app.DownloadPeerToken
}

var _ app.WorkerEnrollmentProofReader = (*WorkerEnrollmentAttester)(nil)

func NewWorkerEnrollmentAttester(c *PermissionClient, b app.WorkerEnrollmentBindings, t app.DownloadPeerToken) (*WorkerEnrollmentAttester, error) {
	if c == nil || b == nil || t == nil {
		return nil, artifact.ErrInvalid
	}
	return &WorkerEnrollmentAttester{c, b, t}, nil
}
func (s *WorkerEnrollmentAttester) ReadWorkerEnrollmentProof(ctx context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	var zero value.WorkerEnrollmentProof
	if s == nil || ctx == nil || !value.UUID(session) || !value.UUID(worker) || key == (artifact.Digest{}) {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	o, e := s.bindings.ReadDownloadWorkerEnrollment(ctx, session, worker)
	if e != nil || !o.Valid(s.client.now()) || o.Worker.Intent.ID != worker || o.Worker.Intent.SessionID != session {
		return zero, artifact.ErrInvalid
	}
	proof, e := acquisitionEnrollmentProof(ctx, s.client, s.tokens, o.Acquisition(), key, start)
	if e != nil {
		return zero, e
	}
	return value.WorkerEnrollmentProof{Worker: o.Worker, PublicKeyDigest: proof.PublicKeyDigest, TokenDigest: proof.TokenDigest, ObservedAt: proof.ObservedAt, FreshUntil: proof.FreshUntil}, nil
}

type AcquisitionEnrollmentAttester struct {
	client   *PermissionClient
	bindings app.AcquisitionEnrollmentBindings
	tokens   app.DownloadPeerToken
}

func NewAcquisitionEnrollmentAttester(c *PermissionClient, b app.AcquisitionEnrollmentBindings, t app.DownloadPeerToken) (*AcquisitionEnrollmentAttester, error) {
	if c == nil || b == nil || t == nil {
		return nil, artifact.ErrInvalid
	}
	return &AcquisitionEnrollmentAttester{c, b, t}, nil
}
func (s *AcquisitionEnrollmentAttester) ReadAcquisitionEnrollmentProof(ctx context.Context, parent value.AcquisitionParent, worker string, key artifact.Digest) (value.AcquisitionWorkerProof, error) {
	var zero value.AcquisitionWorkerProof
	if s == nil || ctx == nil || !parent.Valid() || !value.UUID(worker) || key == (artifact.Digest{}) {
		return zero, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	o, e := s.bindings.ReadAcquisitionEnrollment(ctx, parent, worker)
	if e != nil || !o.Valid(s.client.now()) || o.Worker.Intent.ID != worker || o.Worker.Intent.Parent != parent {
		return zero, artifact.ErrInvalid
	}
	return acquisitionEnrollmentProof(ctx, s.client, s.tokens, o, key, start)
}
func acquisitionEnrollmentProof(ctx context.Context, client *PermissionClient, tokens app.DownloadPeerToken, o value.AcquisitionWorkerIdentity, key artifact.Digest, start time.Time) (value.AcquisitionWorkerProof, error) {
	var zero value.AcquisitionWorkerProof
	w, p := o.Worker, o.Worker.Intent.Profile
	if client.clusterID != p.ClusterID || client.control.Name != p.Namespace || client.control.UID != p.NamespaceUID {
		return zero, artifact.ErrInvalid
	}
	jobs := &DownloadWorkerJobs{client: client, profile: p}
	if jobs.sources(ctx) != nil {
		return zero, artifact.ErrInvalid
	}
	attester, e := NewAcquisitionPeerAttester(client, w.Binding, tokens)
	if e != nil {
		return zero, e
	}
	digest, _, until, e := attester.observeToken(ctx)
	if e != nil || jobs.sources(ctx) != nil {
		return zero, artifact.ErrInvalid
	}
	out := value.AcquisitionWorkerProof{Worker: w, PublicKeyDigest: key, TokenDigest: digest, ObservedAt: start, FreshUntil: identity.Earlier(o.FreshUntil, identity.Earlier(until, start.Add(5*time.Second)))}
	if !out.Valid(client.now()) || ctx.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	return out, nil
}
