package contracts

import (
	"io"
	"time"
)

// InitialBootstrapCopyClosureFormat identifies the original v3 copy-closure profile.
// Fresh installations now select InitialBootstrapVersionedAuditFormat.
// Existing v1/v2 guards retain their original bytes and prohibit copy deletion.
const InitialBootstrapCopyClosureFormat = "asservat-initial-bootstrap/v3"
const InitialBootstrapCopyClaimFormat = "asservat-bootstrap-copy-closure/v1"
const InitialBootstrapCopyClaimMaxBytes = 4096
const InitialBootstrapCopyReceiptMaxBytes = 512
const InitialBootstrapCopyCleanupDuration = 15 * time.Minute

// InitialBootstrapHasPassiveHistory is a closed wire classification, not proof
// of completion, protection, current authority or permission to remove copies.
func InitialBootstrapHasPassiveHistory(format string) bool {
	return format == InitialBootstrapPassiveFormat || InitialBootstrapHasCopyClosure(format)
}

// InitialBootstrapCopyClaim contains original public identities only. Its one
// cleanup interval is persisted before any closure effect and never renewed by
// observation, a process restart, or an uncertain response. Fixed two-copy and
// two-guard operation fields are deliberately not an extensible effect list.
type InitialBootstrapCopyClaim struct {
	Format             string                `json:"format"`
	OperationID        string                `json:"operationID"`
	InstallationID     string                `json:"installationID"`
	RequestID          string                `json:"requestID"`
	Namespace          WorkerObjectReference `json:"namespace"`
	Seed               WorkerObjectReference `json:"seed"`
	Projection         WorkerObjectReference `json:"projection"`
	History            WorkerObjectReference `json:"history"`
	Root               WorkerObjectReference `json:"root"`
	ManagerCloseID     string                `json:"managerCloseID"`
	ManagerRetiredAt   time.Time             `json:"managerRetiredAt"`
	ActivatedClaimID   string                `json:"activatedClaimID"`
	StartedAt          time.Time             `json:"startedAt"`
	Until              time.Time             `json:"until"`
	SQL                WorkerObjectReference `json:"sql"`
	Provider           WorkerObjectReference `json:"provider"`
	PolicyOperationID  string                `json:"policyOperationID"`
	BindingOperationID string                `json:"bindingOperationID"`
}

// InitialBootstrapCopyReceipt is a positive exact object acknowledgement. A
// removal receipt retains the last original UID/resourceVersion used for DELETE;
// its timestamp records a subsequent exact-absence observation under protection.
// The receipt is not current read, effect, SQL or recovery authority.
type InitialBootstrapCopyReceipt struct {
	UID             string    `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
	ObservedAt      time.Time `json:"observedAt"`
}

func DecodeInitialBootstrapCopyClaim(r io.Reader) (InitialBootstrapCopyClaim, error) {
	return decodeClosedRPC[InitialBootstrapCopyClaim](r, InitialBootstrapCopyClaimMaxBytes)
}
func DecodeInitialBootstrapCopyReceipt(r io.Reader) (InitialBootstrapCopyReceipt, error) {
	return decodeClosedRPC[InitialBootstrapCopyReceipt](r, InitialBootstrapCopyReceiptMaxBytes)
}

// InitialBootstrapManagerRetirement is the public projection of the original
// positively completed SQL close. It carries no login material and cannot
// replace current protected SQL handover/history checks.
type InitialBootstrapManagerRetirement struct {
	OperationID string                   `json:"operationID"`
	Manager     InitialSQLHistoryManager `json:"manager"`
	StartedAt   time.Time                `json:"startedAt"`
	Until       time.Time                `json:"until"`
	RetiredAt   time.Time                `json:"retiredAt"`
}

func DecodeInitialBootstrapManagerRetirement(r io.Reader) (InitialBootstrapManagerRetirement, error) {
	return decodeClosedRPC[InitialBootstrapManagerRetirement](r, 512)
}
