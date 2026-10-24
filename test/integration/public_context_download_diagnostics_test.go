package integration

import (
	"context"
	"sync"
	"testing"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Fixture-only original-call diagnostics. No retries, provider text, SQL/argument
// retention, authority reads, clock samples, connection limits or error changes.
// Enrollment counters cover actual delegates, including the overlapping
// requesting operation. SQL capacity diagnostics use the owned server log.
var journeyEnrollmentNames = [...]string{"exchange", "current-authority", "proof", "claim", "prepare", "store", "write-enrollment", "write-certificate", "ack-enrollment", "read-certificate-receipt", "ack-certificate", "issue", "activate", "csr", "legacy-authority"}

type journeyEnrollmentTrace struct {
	mu              sync.Mutex
	calls, refusals [len(journeyEnrollmentNames)]uint32
	reasons         [len(journeyEnrollmentNames)]uint8
	first           int
	stopped         bool
}

func journeyDownloadReason(err error) uint8 {
	switch err {
	case nil:
		return 0
	case context.Canceled:
		return 1
	case context.DeadlineExceeded:
		return 2
	case artifact.ErrDownloadUnavailable:
		return 3
	case artifact.ErrDownloadExpired:
		return 4
	case artifact.ErrDownloadConflict:
		return 5
	case artifact.ErrDownloadCapacity:
		return 6
	case artifact.ErrInvalid:
		return 7
	case artifact.ErrIntegrity:
		return 8
	default:
		return 9
	}
}
func journeyDownloadReasonName(code uint8) string {
	switch code {
	case 0:
		return "none"
	case 1:
		return "canceled"
	case 2:
		return "deadline"
	case 3:
		return "unavailable"
	case 4:
		return "expired"
	case 5:
		return "conflict"
	case 6:
		return "capacity"
	case 7:
		return "invalid"
	case 8:
		return "integrity"
	default:
		return "other"
	}
}
func (s *journeyEnrollmentTrace) record(stage int, err error) {
	code := journeyDownloadReason(err)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || stage < 0 || stage >= len(s.calls) {
		return
	}
	s.calls[stage]++
	if code != 0 {
		s.refusals[stage]++
		if s.reasons[stage] == 0 {
			s.reasons[stage] = code
		}
		if s.first == 0 {
			s.first = stage + 1
		}
	}
}
func (s *journeyEnrollmentTrace) Report(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	for i, n := range journeyEnrollmentNames {
		if s.calls[i] > 0 {
			t.Logf("journey enrollment stage=%s calls=%d refusals=%d reason=%s", n, s.calls[i], s.refusals[i], journeyDownloadReasonName(s.reasons[i]))
		}
	}
	if s.first > 0 {
		t.Logf("journey enrollment first-observed-refusal=%s reason=%s", journeyEnrollmentNames[s.first-1], journeyDownloadReasonName(s.reasons[s.first-1]))
	}
}

type journeyEnrollmentPorts struct {
	evidence.AcquisitionEnrollmentExchange
	evidence.CurrentDownloadAuthority
	evidence.DownloadAuthorityGate
	evidence.WorkerEnrollmentProofReader
	evidence.WorkerEnrollmentLedger
	auditapp.WorkerEnrollmentWriter
	auditapp.WorkerEnrollmentAcknowledgements
	evidence.WorkerCertificateIssuer
	evidence.WorkerCertificateActivator
	evidence.WorkerCSRVerifier
	trace *journeyEnrollmentTrace
}

func (s *journeyEnrollmentTrace) Wrap(in evidence.WorkerEnrollmentCoordinator) evidence.WorkerEnrollmentCoordinator {
	p := journeyEnrollmentPorts{CurrentDownloadAuthority: in.CurrentAuthority, DownloadAuthorityGate: in.Authority, WorkerEnrollmentProofReader: in.Proofs, WorkerEnrollmentLedger: in.Ledger, WorkerEnrollmentWriter: in.Audit, WorkerEnrollmentAcknowledgements: in.Acknowledgements, WorkerCertificateIssuer: in.Issuer, WorkerCertificateActivator: in.Activation, WorkerCSRVerifier: in.CSR, trace: s}
	if in.CurrentAuthority != nil {
		in.CurrentAuthority = p
	}
	if in.Authority != nil {
		in.Authority = p
	}
	if in.Proofs != nil {
		in.Proofs = p
	}
	if in.Ledger != nil {
		in.Ledger = p
	}
	if in.Audit != nil {
		in.Audit = p
	}
	if in.Acknowledgements != nil {
		in.Acknowledgements = p
	}
	if in.Issuer != nil {
		in.Issuer = p
	}
	if in.Activation != nil {
		in.Activation = p
	}
	if in.CSR != nil {
		in.CSR = p
	}
	return in
}
func (d journeyEnrollmentPorts) BeginAcquisitionEnrollment(c context.Context, i string, p value.AcquisitionParent, w string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	v, e := d.AcquisitionEnrollmentExchange.BeginAcquisitionEnrollment(c, i, p, w, token, csr)
	d.trace.record(0, e)
	return v, e
}
func (d journeyEnrollmentPorts) CheckDownloadCurrent(c context.Context, i identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	v, e := d.CurrentDownloadAuthority.CheckDownloadCurrent(c, i, s)
	d.trace.record(1, e)
	return v, e
}
func (d journeyEnrollmentPorts) ReadWorkerEnrollmentProof(c context.Context, s, w string, k artifact.Digest) (value.WorkerEnrollmentProof, error) {
	v, e := d.WorkerEnrollmentProofReader.ReadWorkerEnrollmentProof(c, s, w, k)
	d.trace.record(2, e)
	return v, e
}
func (d journeyEnrollmentPorts) ClaimWorkerEnrollment(c context.Context, p value.WorkerEnrollmentProof) (value.WorkerEnrollment, auditvalue.Receipt, bool, error) {
	v, r, b, e := d.WorkerEnrollmentLedger.ClaimWorkerEnrollment(c, p)
	d.trace.record(3, e)
	return v, r, b, e
}
func (d journeyEnrollmentPorts) PrepareWorkerCertificate(c context.Context, p value.WorkerEnrollmentProof) (value.WorkerCertificateProgress, error) {
	v, e := d.WorkerEnrollmentLedger.PrepareWorkerCertificate(c, p)
	d.trace.record(4, e)
	return v, e
}
func (d journeyEnrollmentPorts) StoreWorkerCertificate(c context.Context, a value.WorkerCertificateAttempt, v value.WorkerCertificate) error {
	e := d.WorkerEnrollmentLedger.StoreWorkerCertificate(c, a, v)
	d.trace.record(5, e)
	return e
}
func (d journeyEnrollmentPorts) WriteWorkerEnrollment(c context.Context, v value.WorkerEnrollment) (auditvalue.Receipt, error) {
	vout, e := d.WorkerEnrollmentWriter.WriteWorkerEnrollment(c, v)
	d.trace.record(6, e)
	return vout, e
}
func (d journeyEnrollmentPorts) WriteWorkerCertificate(c context.Context, v auditvalue.WorkerCertificate) (auditvalue.Receipt, error) {
	vout, e := d.WorkerEnrollmentWriter.WriteWorkerCertificate(c, v)
	d.trace.record(7, e)
	return vout, e
}
func (d journeyEnrollmentPorts) AcknowledgeWorkerEnrollment(c context.Context, v value.WorkerEnrollment, r auditvalue.Receipt) error {
	e := d.WorkerEnrollmentAcknowledgements.AcknowledgeWorkerEnrollment(c, v, r)
	d.trace.record(8, e)
	return e
}
func (d journeyEnrollmentPorts) ReadWorkerCertificateReceipt(c context.Context, v auditvalue.WorkerCertificate) (auditvalue.Receipt, bool, error) {
	r, b, e := d.WorkerEnrollmentAcknowledgements.ReadWorkerCertificateReceipt(c, v)
	d.trace.record(9, e)
	return r, b, e
}
func (d journeyEnrollmentPorts) AcknowledgeWorkerCertificate(c context.Context, v auditvalue.WorkerCertificate, r auditvalue.Receipt) error {
	e := d.WorkerEnrollmentAcknowledgements.AcknowledgeWorkerCertificate(c, v, r)
	d.trace.record(10, e)
	return e
}
func (d journeyEnrollmentPorts) SignWorkerCertificate(c context.Context, a value.WorkerCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	v, e := d.WorkerCertificateIssuer.SignWorkerCertificate(c, a, csr)
	d.trace.record(11, e)
	return v, e
}
func (d journeyEnrollmentPorts) ActivateWorkerCertificate(c context.Context, p value.WorkerEnrollmentProof, a value.WorkerCertificateAttempt) (value.WorkerCertificate, error) {
	out, e := d.WorkerCertificateActivator.ActivateWorkerCertificate(c, p, a)
	d.trace.record(12, e)
	return out, e
}
func (d journeyEnrollmentPorts) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	v, e := d.WorkerCSRVerifier.EnrollmentKey(csr)
	d.trace.record(13, e)
	return v, e
}
func (d journeyEnrollmentPorts) CheckDownload(c context.Context, credential string, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	v, e := d.DownloadAuthorityGate.CheckDownload(c, credential, s)
	d.trace.record(14, e)
	return v, e
}
