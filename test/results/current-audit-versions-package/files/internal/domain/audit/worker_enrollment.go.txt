package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

func WorkerEnrollmentKey(e value.WorkerEnrollment) string {
	return "download-worker-enrollment/v1/" + e.Worker.Binding.InstallationID + "/" + e.Worker.Intent.ID
}
func (r Receipt) ValidWorkerEnrollment(e value.WorkerEnrollment) bool {
	return e.Valid() && r.Version != "" && r.Version != "null" && r.workerReceipt(WorkerEnrollmentKey(e))
}

type WorkerCertificate struct {
	Attempt value.WorkerCertificateAttempt
	Peer    value.KeyPeer
}

func (r WorkerCertificate) Valid() bool {
	a, p := r.Attempt, r.Peer
	b := a.Enrollment.Worker.Binding
	return a.Valid(a.CheckedAt) && p.Valid(a.CheckedAt) && p.InstallationID == b.InstallationID && p.PeerID == b.PodUID && p.Role == "acquisition" && p.NotAfter.Equal(a.CertificateNotAfter) && !p.NotBefore.Before(a.CheckedAt.Add(-time.Minute))
}
func WorkerCertificateKey(c WorkerCertificate) string {
	return "download-worker-certificate/v1/" + c.Attempt.Enrollment.Worker.Binding.InstallationID + "/" + c.Attempt.ID
}
func (r Receipt) ValidWorkerCertificate(c WorkerCertificate) bool {
	return c.Valid() && r.Version != "" && r.Version != "null" && r.workerReceipt(WorkerCertificateKey(c))
}
func (r Receipt) workerReceipt(key string) bool {
	return r.Key == key && (r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
