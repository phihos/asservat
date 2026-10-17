package contracts

import (
	"encoding/base64"
	"io"
)

const WorkerEnrollmentFormat = "asservat-worker-enrollment/v1"
const WorkerEnrollmentPath = "/internal/download-worker/v1/enroll"
const WorkerEnrollmentMaxRequest = 16 << 10
const WorkerEnrollmentMaxResponse = 48 << 10
const WorkerEnrollmentMaxToken = 16 << 10

// No principal, human credential, authority lease, signing period or callback
// address is accepted on this wire. CSR and certificate bytes are DER.
type WorkerEnrollmentRequest struct {
	Format         string `json:"format"`
	InstallationID string `json:"installationID"`
	SessionID      string `json:"sessionID"`
	WorkerID       string `json:"workerID"`
	Nonce          string `json:"nonce"`
	CSR            []byte `json:"csr"`
}

type WorkerEnrollmentResponse struct {
	Format         string   `json:"format"`
	InstallationID string   `json:"installationID"`
	SessionID      string   `json:"sessionID"`
	WorkerID       string   `json:"workerID"`
	Nonce          string   `json:"nonce"`
	Certificate    []byte   `json:"certificate"`
	Chain          [][]byte `json:"chain"`
}

func ValidWorkerNonce(n string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(n)
	return e == nil && len(b) == 32 && len(n) == 43 && base64.RawURLEncoding.EncodeToString(b) == n
}

// Kubernetes projected JWT syntax only. TokenReview supplies authentication.
func ValidWorkerToken(b []byte) bool {
	if len(b) < 1 || len(b) > WorkerEnrollmentMaxToken {
		return false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func DecodeWorkerEnrollmentRequest(r io.Reader) (WorkerEnrollmentRequest, error) {
	return decodeClosedRPC[WorkerEnrollmentRequest](r, WorkerEnrollmentMaxRequest)
}
func DecodeWorkerEnrollmentResponse(r io.Reader) (WorkerEnrollmentResponse, error) {
	return decodeClosedRPC[WorkerEnrollmentResponse](r, WorkerEnrollmentMaxResponse)
}
