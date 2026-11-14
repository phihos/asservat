package contracts

import (
	"time"
)

// The initial batch is a public installation choice, not a live connector or
// permission assignment. Later protected enrollment does not edit this batch.
type OwnerBootstrapPlan struct {
	ObservationFormat string                   `json:"observationFormat,omitempty"`
	Format            string                   `json:"format"`
	PKIMount          string                   `json:"pkiMount"`
	Connections       int                      `json:"connections"`
	Concurrency       int                      `json:"concurrency"`
	Peers             []OwnerBootstrapPeerPlan `json:"peers"`
}
type OwnerBootstrapPeerPlan struct {
	ClusterID string   `json:"clusterID"`
	Roots     [][]byte `json:"roots"`
}

// Only compact allocation facts enter the original 32KiB resource journal.
// The separate child attempt has its own one-use CREATE and original deadline.
type OwnerBootstrapSelectionClaim struct {
	ObservationFormat string                         `json:"observationFormat,omitempty"`
	IssuerEpoch       string                         `json:"issuerEpoch"`
	OperationID       string                         `json:"operationID"`
	PermissionRootID  string                         `json:"permissionRootID"`
	PKIMount          string                         `json:"pkiMount"`
	Connections       int                            `json:"connections"`
	Concurrency       int                            `json:"concurrency"`
	Peers             []OwnerBootstrapPeerAllocation `json:"peers"`
	PublicDigest      string                         `json:"publicDigest"`
	ClaimedAt         time.Time                      `json:"claimedAt"`
	Until             time.Time                      `json:"until"`
	Child             *OwnerBootstrapObjectAttempt   `json:"child,omitempty"`
}
type OwnerBootstrapPeerAllocation struct {
	ClusterID   string `json:"clusterID"`
	PeerID      string `json:"peerID"`
	RootsDigest string `json:"rootsDigest"`
}
type OwnerBootstrapObjectAttempt struct {
	OperationID string                       `json:"operationID"`
	ClaimedAt   time.Time                    `json:"claimedAt"`
	Until       time.Time                    `json:"until"`
	Receipt     *OwnerBootstrapObjectReceipt `json:"receipt,omitempty"`
}
type OwnerBootstrapObjectReceipt struct {
	Object          WorkerObjectReference `json:"object"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}
