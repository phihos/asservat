package contracts

// SmallOpenBaoPrepared contains public provenance only. It grants no provider,
// installation, recovery or evidence authority. ReadyPVCUID is empty until the
// trusted setup has independently verified the original backend's final marker.
type SmallOpenBaoPrepared struct {
	State       WorkerObjectReference
	BackendID   string
	RootsPEM    []byte
	ReadyPVCUID string
}

const SmallOpenBaoBackendAnnotation = "asservat.io/openbao-backend-id"
const SmallOpenBaoReadyAnnotation = "asservat.io/openbao-ready"
