package contracts

import "io"

const InitialPreparationFormat = "asservat-initial-preparation/v1"
const InitialPreparationMaxBytes = 48 << 10
const InitialPreparationMaxCreates = 64

// Public installation provenance only. Never include credentials, evidence,
// provider replies or hashes of secret payloads in this ConfigMap document.
type InitialPreparation struct {
	Format         string                     `json:"format"`
	InstallationID string                     `json:"installationID"`
	RequestID      string                     `json:"requestID"`
	PlanDigest     string                     `json:"planDigest"`
	Namespace      WorkerObjectReference      `json:"namespace"`
	Guard          OwnerDeploymentGuard       `json:"guard"`
	Creates        []InitialPreparationCreate `json:"creates"`
}

type InitialPreparationCreate struct {
	OperationID string                     `json:"operationID"`
	Kind        string                     `json:"kind"`
	Name        string                     `json:"name"`
	SpecDigest  string                     `json:"specDigest"`
	Receipt     *InitialPreparationReceipt `json:"receipt,omitempty"`
}

type InitialPreparationReceipt struct {
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

func DecodeInitialPreparation(r io.Reader) (InitialPreparation, error) {
	return decodeClosedRPC[InitialPreparation](r, InitialPreparationMaxBytes)
}
