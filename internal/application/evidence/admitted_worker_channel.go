package evidence

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type AcquisitionProofFactory func(DownloadPeerToken) (AcquisitionEnrollmentProofReader, error)

// AdmittedWorkerEnrollment serves the two closed parent purposes locally. The
// worker's HTTP lifetime owns all work and response delivery. There is no human
// request registry, locator publication or certificate relay. The same exact
// admitted Pod must still pass actual TokenReview, object and configuration
// attestation; the resulting certificate grants no evidence authority.
type AdmittedWorkerEnrollment struct {
	InstallationID   string
	Bindings         AcquisitionEnrollmentBindings
	Download         WorkerEnrollmentCoordinator
	DownloadProofs   WorkerProofFactory
	Projection       ProjectionEnrollmentCoordinator
	ProjectionProofs AcquisitionProofFactory
	Now              func() time.Time
}

func (s *AdmittedWorkerEnrollment) BeginAcquisitionEnrollment(ctx context.Context, installation string, parent value.AcquisitionParent, worker string, token, csr []byte) (WorkerEnrollmentDelivery, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Now == nil || s.Bindings == nil || installation != s.InstallationID || !value.UUID(installation) || !parent.Valid() || !value.UUID(worker) || len(token) < 1 || len(token) > 16<<10 || len(csr) < 1 || len(csr) > 8192 {
		return nil, artifact.ErrDownloadUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	keep := false
	defer func() {
		if !keep {
			cancel()
		}
	}()
	original, e := s.Bindings.ReadAcquisitionEnrollment(call, parent, worker)
	if e != nil || !original.Valid(s.Now()) || original.Worker.Intent.ID != worker || original.Worker.Intent.Parent != parent || original.Worker.Binding.InstallationID != installation || call.Err() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	until, _ := call.Deadline()
	until = identity.Earlier(until, original.Worker.Intent.RunUntil)
	limited, stop := context.WithDeadline(call, until)
	defer func() {
		if !keep {
			stop()
		}
	}()
	owned := enrollmentToken(bytes.Clone(token))
	defer clear(owned)
	var certificate value.WorkerCertificate
	switch parent.Purpose {
	case value.AcquisitionDownload:
		if s.DownloadProofs == nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		proof, err := s.DownloadProofs(owned)
		if err != nil || proof == nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		service := s.Download
		service.Proofs = targetWorkerProof{reader: proof, target: original.Worker.CredentialTarget()}
		certificate, e = service.EnrollAdmitted(limited, parent.ID, worker, csr)
	case value.AcquisitionProjection:
		if s.ProjectionProofs == nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		proof, err := s.ProjectionProofs(owned)
		if err != nil || proof == nil {
			return nil, artifact.ErrDownloadUnavailable
		}
		service := s.Projection
		service.Proofs = targetAcquisitionProof{reader: proof, worker: original.Worker}
		certificate, e = service.EnrollProjection(limited, parent, worker, csr)
	default:
		return nil, artifact.ErrDownloadUnavailable
	}
	if e != nil {
		return nil, e
	}
	// Final identity validation consumes a new current read; it never recreates
	// the admitted lifetime. Hold that read's original bound through socket write.
	final, e := s.Bindings.ReadAcquisitionEnrollment(limited, parent, worker)
	if e != nil || !final.Valid(s.Now()) || final.Worker != original.Worker || limited.Err() != nil || !certificate.Peer.Valid(s.Now()) || certificate.Peer.InstallationID != installation || certificate.Peer.PeerID != original.Worker.Binding.PodUID || certificate.Peer.Role != "acquisition" || certificate.Peer.NotAfter.After(original.Worker.Intent.RunUntil) {
		return nil, artifact.ErrDownloadUnavailable
	}
	response, end := context.WithDeadline(limited, identity.Earlier(final.FreshUntil, certificate.Peer.NotAfter))
	if response.Err() != nil {
		end()
		return nil, artifact.ErrDownloadExpired
	}
	keep = true
	return &workerEnrollmentDelivery{ctx: response, certificate: certificate, release: func() { end(); stop(); cancel() }}, nil
}

type targetAcquisitionProof struct {
	reader AcquisitionEnrollmentProofReader
	worker value.AcquisitionWorker
}

func (s targetAcquisitionProof) ReadAcquisitionEnrollmentProof(ctx context.Context, parent value.AcquisitionParent, worker string, key artifact.Digest) (value.AcquisitionWorkerProof, error) {
	p, e := s.reader.ReadAcquisitionEnrollmentProof(ctx, parent, worker, key)
	if e != nil || p.Worker != s.worker || p.Worker.Intent.Parent != parent || p.Worker.Intent.ID != worker || p.PublicKeyDigest != key {
		return value.AcquisitionWorkerProof{}, artifact.ErrDownloadUnavailable
	}
	return p, nil
}
