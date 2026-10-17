package contracts

import (
	"io"
	"strings"
	"time"
)

const OwnerBootstrapPlanFormat = "asservat-owner-bootstrap-plan/v1"
const OwnerBootstrapSelectionFormat = "asservat-owner-bootstrap-selection/v1"
const OwnerBootstrapSelectionFile = "owner-bootstrap.json"
const OwnerBootstrapInitialPeers = 16

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

// The immutable child carries the full public roots. Its own UID and CREATE
// attempt are intentionally outside its body, avoiding self-reference cycles.
type OwnerBootstrapSelection struct {
	ObservationFormat string                 `json:"observationFormat,omitempty"`
	InitialFormat     string                 `json:"initialFormat"`
	Format            string                 `json:"format"`
	InstallationID    string                 `json:"installationID"`
	ControlClusterID  string                 `json:"controlClusterID"`
	IssuerEpoch       string                 `json:"issuerEpoch"`
	Namespace         WorkerObjectReference  `json:"namespace"`
	Resources         WorkerObjectReference  `json:"resources"`
	ResourceSetupID   string                 `json:"resourceSetupID"`
	ResourceBinding   string                 `json:"resourceBinding"`
	OperationID       string                 `json:"operationID"`
	PermissionRootID  string                 `json:"permissionRootID"`
	PKIMount          string                 `json:"pkiMount"`
	Connections       int                    `json:"connections"`
	Concurrency       int                    `json:"concurrency"`
	Peers             []OwnerObservationPeer `json:"peers"`
}

func OwnerBootstrapSelectionName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-owner-bootstrap"
}
func DecodeOwnerBootstrapPlan(r io.Reader) (OwnerBootstrapPlan, error) {
	return decodeClosedRPC[OwnerBootstrapPlan](r, OwnerDeploymentMaxBytes)
}
func DecodeOwnerBootstrapSelection(r io.Reader) (OwnerBootstrapSelection, error) {
	return decodeClosedRPC[OwnerBootstrapSelection](r, OwnerDeploymentMaxBytes)
}
