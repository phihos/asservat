package contracts

import (
	"errors"
	"io"
	"time"
)

// ADR-246: the private node work channel (I-02) between the `asservat node`
// DaemonSet and its cluster connector. The node initiates every request over
// TLS 1.3; enrollment presents a Pod-bound projected token and an
// identity-free CSR, every later request a connector-issued client
// certificate. No human credential, Kubernetes writer token, evidence or key
// material crosses this wire.
const (
	NodeDeploymentFormat   = "asservat-node-deployment/v1"
	NodeDeploymentRoot     = "/run/asservat/node"
	NodeDeploymentFile     = "node.json"
	NodeDeploymentMaxBytes = 64 << 10
	NodeTokenRoot          = "/run/asservat/node-token"
	NodeTokenFile          = "token"
	NodePodUIDEnvironment  = "ASSERVAT_NODE_POD_UID"
	NodeNameEnvironment    = "ASSERVAT_NODE_NAME"
	// NodeDisposableHostGuard is the accidental-use barrier of the S-04 test
	// environment (plan §5.2): the collector refuses to start, and the chart's
	// hostPath of type File keeps the Pod from starting, unless the host
	// carries this file. Only disposable CI runners and VM images create it.
	NodeDisposableHostGuard = "/etc/asservat-disposable-host"

	NodeEnrollFormat   = "asservat-node-enroll/v1"
	NodePollFormat     = "asservat-node-poll/v1"
	NodeStatusFormat   = "asservat-node-status/v1"
	NodeEnrollPath     = "/internal/v1/node/enroll"
	NodePollPath       = "/internal/v1/node/poll"
	NodeStatusPath     = "/internal/v1/node/status"
	NodeMaxRequest     = 64 << 10
	NodeMaxResponse    = 64 << 10
	NodeMaxCertificate = 8 << 10
)

var ErrNodeChannel = errors.New("node channel message rejected")

// NodeTokenAudience is the dedicated projected-token audience of one
// installation's node collectors; no other component accepts it.
func NodeTokenAudience(installationID string) string { return "asservat-node:" + installationID }

// NodeDeployment is the collector's installation-owned public input, mounted
// from the chart's ConfigMap. Ceilings are the local administrator's
// collector-wide budgets (specs/capacity.md).
type NodeDeployment struct {
	Format         string                `json:"format"`
	InstallationID string                `json:"installationID"`
	ClusterID      string                `json:"clusterID"`
	Connector      NodeConnectorEndpoint `json:"connector"`
	Ceilings       NodeCeilings          `json:"ceilings"`
}

// NodeConnectorEndpoint pins the connector's node listener, the server name
// its certificate must carry and the roots that issued it.
type NodeConnectorEndpoint struct {
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"serverName"`
	RootsPEM   string `json:"rootsPEM"`
}

type NodeCeilings struct {
	RingBytes            int64 `json:"ringBytes"`
	FrozenBytes          int64 `json:"frozenBytes"`
	UploadBytesPerSecond int64 `json:"uploadBytesPerSecond"`
	UploadBurstBytes     int64 `json:"uploadBurstBytes"`
}

// NodeEnrollRequest carries the projected token, a DER identity-free CSR, the
// kernel boot ID and the process's random epoch. The server assigns identity.
type NodeEnrollRequest struct {
	Format string `json:"format"`
	Token  string `json:"token"`
	CSR    []byte `json:"csr"`
	BootID string `json:"bootID"`
	Epoch  string `json:"epoch"`
}

type NodeEnrollResponse struct {
	Format      string    `json:"format"`
	Certificate []byte    `json:"certificate"`
	NotAfter    time.Time `json:"notAfter"`
	NodeName    string    `json:"nodeName"`
	NodeUID     string    `json:"nodeUID"`
}

// NodePollRequest asks for work after the last sequence the node has seen.
type NodePollRequest struct {
	Format string `json:"format"`
	Epoch  string `json:"epoch"`
	After  uint64 `json:"after"`
}

type NodePollResponse struct {
	Format string     `json:"format"`
	Work   []NodeWork `json:"work"`
}

// NodeWork is one closed work item: armSource, stopSource, snapshot or
// peerGeneration. Typed payloads arrive with the increments that implement
// the recorders; an item of this version carries only its identity.
type NodeWork struct {
	ID       string    `json:"id"`
	Sequence uint64    `json:"sequence"`
	Kind     string    `json:"kind"`
	NotAfter time.Time `json:"notAfter"`
}

// NodeStatus is one batched report: probed facts, mechanism assessment, node
// budget usage and receipts for work seen since the previous report.
type NodeStatus struct {
	Format     string        `json:"format"`
	Epoch      string        `json:"epoch"`
	Sequence   uint64        `json:"sequence"`
	ObservedAt time.Time     `json:"observedAt"`
	Probe      NodeProbe     `json:"probe"`
	Mechanisms []NodeAdapter `json:"mechanisms"`
	Budget     NodeBudget    `json:"budget"`
	Receipts   []NodeReceipt `json:"receipts"`
}

type NodeProbe struct {
	KernelRelease string     `json:"kernelRelease"`
	Kernel        string     `json:"kernel"`
	BTF           string     `json:"btf"`
	CgroupV2      string     `json:"cgroupV2"`
	BPF           string     `json:"bpf"`
	TCX           string     `json:"tcx"`
	TC            string     `json:"tc"`
	DebugFS       string     `json:"debugfs"`
	TraceFS       string     `json:"tracefs"`
	BPFFS         string     `json:"bpffs"`
	HostProcesses string     `json:"hostProcesses"`
	Runtime       string     `json:"runtime"`
	Engine        NodeEngine `json:"engine"`
}

type NodeEngine struct {
	Linked      bool   `json:"linked"`
	Initialized bool   `json:"initialized"`
	Version     string `json:"version"`
}

type NodeAdapter struct {
	Mechanism     string   `json:"mechanism"`
	Prerequisites bool     `json:"prerequisites"`
	Adapter       string   `json:"adapter"`
	Hook          string   `json:"hook"`
	Reasons       []string `json:"reasons"`
}

type NodeBudget struct {
	Ceilings        NodeCeilings `json:"ceilings"`
	RingReserved    int64        `json:"ringReserved"`
	FrozenReserved  int64        `json:"frozenReserved"`
	UploadAvailable int64        `json:"uploadAvailable"`
}

type NodeReceipt struct {
	WorkID   string `json:"workID"`
	Sequence uint64 `json:"sequence"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
}

func nodeDecode[T any](r io.Reader, limit int64) (T, error) {
	out, err := decodeClosedRPC[T](r, limit)
	if err != nil {
		var zero T
		return zero, ErrNodeChannel
	}
	return out, nil
}

func DecodeNodeDeployment(r io.Reader) (NodeDeployment, error) {
	return nodeDecode[NodeDeployment](r, NodeDeploymentMaxBytes)
}
func DecodeNodeEnrollRequest(r io.Reader) (NodeEnrollRequest, error) {
	return nodeDecode[NodeEnrollRequest](r, NodeMaxRequest)
}
func DecodeNodeEnrollResponse(r io.Reader) (NodeEnrollResponse, error) {
	return nodeDecode[NodeEnrollResponse](r, NodeMaxResponse)
}
func DecodeNodePollRequest(r io.Reader) (NodePollRequest, error) {
	return nodeDecode[NodePollRequest](r, NodeMaxRequest)
}
func DecodeNodePollResponse(r io.Reader) (NodePollResponse, error) {
	return nodeDecode[NodePollResponse](r, NodeMaxResponse)
}
func DecodeNodeStatus(r io.Reader) (NodeStatus, error) {
	return nodeDecode[NodeStatus](r, NodeMaxRequest)
}
