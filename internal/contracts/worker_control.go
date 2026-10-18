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
//
// Address, when present, is the "host:port" the worker dials for Endpoint. It
// selects connectivity only: the TLS server name and HTTP authority remain
// Endpoint's and are verified against ServerRoots. A hub-local worker uses it
// to reach the owner Service while verifying the owner pool's fixed serving
// name (ADR-204 decision 9). Absent, the worker dials Endpoint's own host.
type WorkerControl struct {
	Format         string               `json:"format"`
	InstallationID string               `json:"installationID"`
	ClusterID      string               `json:"clusterID"`
	Endpoint       string               `json:"endpoint"`
	Address        string               `json:"address,omitempty"`
	ServerRoots    [][]byte             `json:"serverRoots"`
	IssuerRoots    [][]byte             `json:"issuerRoots"`
	Native         *WorkerNativeControl `json:"native,omitempty"`
}

func DecodeWorkerControl(r io.Reader) (WorkerControl, error) {
	return decodeClosedRPC[WorkerControl](r, WorkerControlMaxBytes)
}
