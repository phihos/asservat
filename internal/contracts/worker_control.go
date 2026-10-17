package contracts

import "io"

const WorkerControlFormat = "asservat-worker-control/v1"
const WorkerNativeControlFormat = "asservat-worker-control/v2"
const WorkerControlMaxBytes = 64 << 10
const WorkerTokenPath = "/run/asservat/identity/token"
const WorkerControlPath = "/run/asservat/control/worker.json"
const WorkerPodUIDEnvironment = "ASSERVAT_WORKER_POD_UID"

// Immutable installation data only. No private key, executable, source object,
// evidence authority, human credential or arbitrary callback is accepted.
type WorkerControl struct {
	Format         string               `json:"format"`
	InstallationID string               `json:"installationID"`
	ClusterID      string               `json:"clusterID"`
	Endpoint       string               `json:"endpoint"`
	ServerRoots    [][]byte             `json:"serverRoots"`
	IssuerRoots    [][]byte             `json:"issuerRoots"`
	Native         *WorkerNativeControl `json:"native,omitempty"`
}

func DecodeWorkerControl(r io.Reader) (WorkerControl, error) {
	return decodeClosedRPC[WorkerControl](r, WorkerControlMaxBytes)
}
