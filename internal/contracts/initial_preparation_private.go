package contracts

import (
	"io"
	"time"
)

const InitialPreparationPrivateFormat = "asservat-initial-preparation-private/v1"
const InitialPreparationPrivateMaxBytes = 16 << 10

// Producer-owned private progress at one independently pinned Secret UID. Never
// copy this body or a digest of it into the public journal, audit or diagnostics.
// Initial bootstrap supplies only Format/InstallationID/RequestID. The producer
// freezes the actual root binding before any credential issuance.
type InitialPreparationPrivateState struct {
	Providers      *InitialPreparationProviders `json:"providers,omitempty"`
	SQL            *InitialPreparationSQLState  `json:"sql,omitempty"`
	Format         string                       `json:"format"`
	InstallationID string                       `json:"installationID"`
	RequestID      string                       `json:"requestID"`
	RootUID        string                       `json:"rootUID,omitempty"`
	PlanDigest     string                       `json:"planDigest,omitempty"`
	Probe          *InitialPreparationProbe     `json:"probe,omitempty"`
}

type InitialPreparationProbe struct {
	CreateClosed      bool                          `json:"createClosed,omitempty"`
	AnchorOperationID string                        `json:"anchorOperationID"`
	Anchor            *InitialPreparationReceipt    `json:"anchor,omitempty"`
	Issue             *InitialPreparationProbeIssue `json:"issue,omitempty"`
}
type InitialPreparationProbeIssue struct {
	ID            string                           `json:"id"`
	Audience      string                           `json:"audience"`
	StartedAt     time.Time                        `json:"startedAt"`
	Until         time.Time                        `json:"until"`
	ExpiresBefore time.Time                        `json:"expiresBefore"`
	Response      *InitialPreparationProbeResponse `json:"response,omitempty"`
}
type InitialPreparationProbeResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func DecodeInitialPreparationPrivateState(r io.Reader) (InitialPreparationPrivateState, error) {
	return decodeClosedRPC[InitialPreparationPrivateState](r, InitialPreparationPrivateMaxBytes)
}
func (InitialPreparationPrivateState) String() string {
	return "protected initial preparation progress"
}
func (InitialPreparationPrivateState) GoString() string {
	return "protected initial preparation progress"
}
func (InitialPreparationProbeIssue) String() string      { return "protected initial probe issuance" }
func (InitialPreparationProbeIssue) GoString() string    { return "protected initial probe issuance" }
func (InitialPreparationProbeResponse) String() string   { return "protected initial probe credential" }
func (InitialPreparationProbeResponse) GoString() string { return "protected initial probe credential" }

// One original immutable target-state CREATE. This records private persistence,
// never proof of SQL activation or permission to reissue/reset credentials.
type InitialPreparationSQLState struct {
	CreateClosed bool                   `json:"createClosed,omitempty"`
	OperationID  string                 `json:"operationID"`
	Secret       *WorkerObjectReference `json:"secret,omitempty"`
}
