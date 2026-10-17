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
	w, p := o.Worker, o.Worker.Intent.Profile
	if s.client.clusterID != p.ClusterID || s.client.control.Name != p.Namespace || s.client.control.UID != p.NamespaceUID {
		return zero, artifact.ErrInvalid
	}
	jobs := &DownloadWorkerJobs{client: s.client, profile: p}
	if jobs.sources(ctx) != nil {
		return zero, artifact.ErrInvalid
	}
	attester, e := NewDownloadPeerAttester(s.client, w.Binding, s.tokens)
	if e != nil {
		return zero, e
	}
	digest, _, until, e := attester.observeToken(ctx)
	if e != nil || jobs.sources(ctx) != nil {
		return zero, artifact.ErrInvalid
	}
	out := value.WorkerEnrollmentProof{Worker: w, PublicKeyDigest: key, TokenDigest: digest, ObservedAt: start, FreshUntil: identity.Earlier(o.FreshUntil, identity.Earlier(until, start.Add(5*time.Second)))}
	if !out.Valid(s.client.now()) || ctx.Err() != nil {
		return zero, artifact.ErrDownloadExpired
	}
	return out, nil
}
