package audit

import (
	"asservat.local/asservat/internal/domain/analysis"
	value "asservat.local/asservat/internal/domain/authorization"
	"time"
)

// Download audit keys/records retain their original formats. These closed
// approved-query records use the same encrypted control-audit writer.
func ProjectionWorkerKey(i analysis.ContextProjectionWorkerIntent) string {
	return "context-query-worker/v1/" + i.Query.Scope.RootID + "/" + i.Query.ID + "/" + i.Worker.ID + "/intent"
}
func (r Receipt) ValidProjectionWorker(i analysis.ContextProjectionWorkerIntent) bool {
	return i.Valid() && r.Version != "" && r.Version != "null" && r.workerReceipt(ProjectionWorkerKey(i))
}
func AcquisitionEnrollmentKey(e value.AcquisitionEnrollment) string {
	return "acquisition-enrollment/v1/" + string(e.Worker.Intent.Parent.Purpose) + "/" + e.Worker.Binding.InstallationID + "/" + e.Worker.Intent.ID
}
func (r Receipt) ValidAcquisitionEnrollment(e value.AcquisitionEnrollment) bool {
	return e.Valid() && r.Version != "" && r.Version != "null" && r.workerReceipt(AcquisitionEnrollmentKey(e))
}

type AcquisitionCertificate struct {
	Attempt value.AcquisitionCertificateAttempt
	Peer    value.KeyPeer
}

func (r AcquisitionCertificate) Valid() bool {
	a, p := r.Attempt, r.Peer
	b := a.Enrollment.Worker.Binding
	return a.Valid(a.CheckedAt) && p.Valid(a.CheckedAt) && p.InstallationID == b.InstallationID && p.PeerID == b.PodUID && p.Role == "acquisition" && p.NotAfter.Equal(a.CertificateNotAfter) && !p.NotBefore.Before(a.CheckedAt.Add(-time.Minute))
}
func AcquisitionCertificateKey(c AcquisitionCertificate) string {
	return "acquisition-certificate/v1/" + string(c.Attempt.Enrollment.Worker.Intent.Parent.Purpose) + "/" + c.Peer.InstallationID + "/" + c.Attempt.ID
}
func (r Receipt) ValidAcquisitionCertificate(c AcquisitionCertificate) bool {
	return c.Valid() && r.Version != "" && r.Version != "null" && r.workerReceipt(AcquisitionCertificateKey(c))
}
