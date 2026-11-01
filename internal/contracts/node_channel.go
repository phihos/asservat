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

	NodeEnrollFormat = "asservat-node-enroll/v1"
	NodePollFormat   = "asservat-node-poll/v1"
	NodeStatusFormat = "asservat-node-status/v1"
	NodeEnrollPath   = "/internal/v1/node/enroll"
	NodePollPath     = "/internal/v1/node/poll"
	NodeStatusPath   = "/internal/v1/node/status"
	NodeMaxRequest   = 64 << 10
	// At most1088 content-free source accounting rows plus existing facts.
	// Enrollment and poll requests keep their existing64KiB bound.
	NodeStatusMaxRequest = 512 << 10
	// NodeMaxResponse bounds one poll answer: 16 items, each packet capture
	// with at most 256 filter instructions (ADR-248).
	NodeMaxResponse    = 256 << 10
	NodeMaxCertificate = 8 << 10

	// ADR-248: a finished packet capture travels node → connector as one
	// request: a 4-byte big-endian header length, the JSON NodePacketResult
	// header, then exactly CapturedBytes of PCAPNG.
	NodeCaptureFormat      = "asservat-node-capture/v1"
	NodeCapturePath        = "/internal/v1/node/capture"
	NodeCaptureContentType = "application/vnd.asservat.node-capture"
	NodeCaptureMaxHeader   = 4 << 10
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
	MaxActiveSources     int64 `json:"maxActiveSources,omitempty"`
	InputBytesPerSecond  int64 `json:"inputBytesPerSecond,omitempty"`
	InputBurstBytes      int64 `json:"inputBurstBytes,omitempty"`
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

// NodeWork is one closed work item: armSource, stopSource, snapshot,
// peerGeneration or packetCapture. Only packetCapture (ADR-248) carries a
// typed payload in this version; the others carry only their identity.
type NodeWork struct {
	ID                   string              `json:"id"`
	Sequence             uint64              `json:"sequence"`
	Kind                 string              `json:"kind"`
	NotAfter             time.Time           `json:"notAfter"`
	PacketCapture        *NodePacketCapture  `json:"packetCapture,omitempty"`
	PacketSource         *NodePacketSource   `json:"packetSource,omitempty"`
	CancelSourceSnapshot *NodeSourceSnapshot `json:"cancelSourceSnapshot,omitempty"`
	SourceSnapshot       *NodeSourceSnapshot `json:"sourceSnapshot,omitempty"`
	StopPacketSource     *NodeSourceBinding  `json:"stopPacketSource,omitempty"`
}

// NodePacketSource is a distinct ordinary ongoing work purpose. Older nodes
// reject these fields/kinds rather than interpreting them as a finite capture.
type NodePacketSource struct {
	Permit            NodeSourcePermit     `json:"permit"`
	Program           []NodeBPFInstruction `json:"program"`
	Ring              NodeSourceRingLimits `json:"ring"`
	ResourcePolicyUID string               `json:"resourcePolicyUID"`
	NodeLimits        NodeCeilings         `json:"nodeLimits"`
	WorkloadLimits    NodeSourceLimits     `json:"workloadLimits"`
}
type NodeSourceLimits struct {
	MaxActiveSources    int64 `json:"maxActiveSources"`
	InputBytesPerSecond int64 `json:"inputBytesPerSecond"`
	InputBurstBytes     int64 `json:"inputBurstBytes"`
}
type NodeSourcePermit struct {
	Binding        NodeSourceBinding `json:"binding"`
	StartedAt      time.Time         `json:"startedAt"`
	HardUntil      time.Time         `json:"hardUntil"`
	StartBy        time.Time         `json:"startBy"`
	IssuedAt       time.Time         `json:"issuedAt"`
	DispatchUntil  time.Time         `json:"dispatchUntil"`
	LeafUntil      time.Time         `json:"leafUntil"`
	Credit         int64             `json:"credit"`
	BytesPerSecond int64             `json:"bytesPerSecond"`
}
type NodeSourceBinding struct {
	AudienceDigest    string `json:"audienceDigest,omitempty"`
	RootID            string `json:"rootID"`
	PolicyUID         string `json:"policyUID"`
	AcceptanceID      string `json:"acceptanceID"`
	SourceID          string `json:"sourceID"`
	Fence             string `json:"fence"`
	ActionID          string `json:"actionID"`
	PodUID            string `json:"podUID"`
	NodeUID           string `json:"nodeUID"`
	BootID            string `json:"bootID"`
	CollectorPodUID   string `json:"collectorPodUID"`
	CollectorEpoch    string `json:"collectorEpoch"`
	Scope             string `json:"scope"`
	ExpectationDigest string `json:"expectationDigest"`
	ProgramDigest     string `json:"programDigest"`
	ResourceDigest    string `json:"resourceDigest"`
}
type NodeSourceRingLimits struct {
	MaxAgeNanos            int64 `json:"maxAgeNanos"`
	MaxBytes               int64 `json:"maxBytes"`
	SegmentBytes           int64 `json:"segmentBytes"`
	MaxFrozenBytes         int64 `json:"maxFrozenBytes"`
	MaxSegments            int   `json:"maxSegments"`
	MaxConcurrentSnapshots int   `json:"maxConcurrentSnapshots"`
}

// NodePacketCapture is one manual networkHeaders capture of one Pod. Program
// is the hub-compiled classic BPF program (empty: all traffic) and
// ProgramDigest its SHA-256 over little-endian struct sock_filter bytes in
// lowercase hex (empty with an empty program).
type NodePacketCapture struct {
	CaptureID      string                 `json:"captureID"`
	PodUID         string                 `json:"podUID"`
	Program        []NodeBPFInstruction   `json:"program"`
	ProgramDigest  string                 `json:"programDigest"`
	DurationMillis int64                  `json:"durationMillis"`
	MaxBytes       int64                  `json:"maxBytes"`
	Observation    *NodeObservationPermit `json:"observation,omitempty"`
}

// NodeObservationPermit carries one committed finite original allowance over
// the authenticated node channel. Digests use the existing lowercase hex codec.
type NodeObservationPermit struct {
	Binding        NodeObservationBinding `json:"binding"`
	StartedAt      time.Time              `json:"startedAt"`
	SessionUntil   time.Time              `json:"sessionUntil"`
	LeaseUntil     time.Time              `json:"leaseUntil"`
	StartBy        time.Time              `json:"startBy"`
	DurationMillis int64                  `json:"durationMillis"`
	Sequence       uint64                 `json:"sequence"`
	Credit         int64                  `json:"credit"`
	BytesPerSecond int64                  `json:"bytesPerSecond"`
}

type NodeObservationBinding struct {
	Scope             string `json:"scope"`
	ProgramDigest     string `json:"programDigest"`
	ExpectationDigest string `json:"expectationDigest"`
	AccountingRule    string `json:"accountingRule"`
	SessionID         string `json:"sessionID"`
	Fence             string `json:"fence"`
	CaptureID         string `json:"captureID"`
	ActionID          string `json:"actionID"`
	PodUID            string `json:"podUID"`
	NodeUID           string `json:"nodeUID"`
	BootID            string `json:"bootID"`
	CollectorPodUID   string `json:"collectorPodUID"`
	CollectorEpoch    string `json:"collectorEpoch"`
}

type NodeBPFInstruction struct {
	Code uint16 `json:"code"`
	Jt   uint8  `json:"jt"`
	Jf   uint8  `json:"jf"`
	K    uint32 `json:"k"`
}

// NodePacketResult heads one finished capture upload.
type NodePacketResult struct {
	Snapshot      *NodeSnapshotOutcome `json:"snapshot,omitempty"`
	Format        string               `json:"format"`
	Epoch         string               `json:"epoch"`
	WorkID        string               `json:"workID"`
	CaptureID     string               `json:"captureID"`
	StartedAt     time.Time            `json:"startedAt"`
	EndedAt       time.Time            `json:"endedAt"`
	Seen          uint64               `json:"seen"`
	Retained      uint64               `json:"retained"`
	Filtered      uint64               `json:"filtered"`
	Unsupported   uint64               `json:"unsupported"`
	Fragment      uint64               `json:"fragment"`
	Extension     uint64               `json:"extension"`
	Malformed     uint64               `json:"malformed"`
	OutputFull    uint64               `json:"outputFull"`
	LostSamples   uint64               `json:"lostSamples"`
	WireBytes     uint64               `json:"wireBytes"`
	CapturedBytes int64                `json:"capturedBytes"`
	Snaplen       int                  `json:"snaplen"`
	EngineVersion string               `json:"engineVersion"`
	ProgramDigest string               `json:"programDigest"`
	Failure       string               `json:"failure"`
}

// NodeStatus is one batched report: probed facts, mechanism assessment, node
// budget usage and receipts for work seen since the previous report.
type NodeStatus struct {
	Format     string             `json:"format"`
	Epoch      string             `json:"epoch"`
	Sequence   uint64             `json:"sequence"`
	ObservedAt time.Time          `json:"observedAt"`
	Probe      NodeProbe          `json:"probe"`
	Mechanisms []NodeAdapter      `json:"mechanisms"`
	Budget     NodeBudget         `json:"budget"`
	Receipts   []NodeReceipt      `json:"receipts"`
	Sources    []NodeSourceStatus `json:"sources,omitempty"`
}

type NodeSourceStatus struct {
	SourceStoppedAt time.Time `json:"sourceStoppedAt,omitzero"`
	SnapshotUntil   time.Time `json:"snapshotUntil,omitzero"`
	SourceID        string    `json:"sourceID"`
	Fence           string    `json:"fence"`
	IssuedAt        time.Time `json:"issuedAt"`
	LeafUntil       time.Time `json:"leafUntil"`
	Credit          int64     `json:"credit"`
	ObservedBytes   int64     `json:"observedBytes"`
	Closed          bool      `json:"closed"`
	Stopped         bool      `json:"stopped"`
	InputUnknown    bool      `json:"inputUnknown"`
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
	return nodeDecode[NodeStatus](r, NodeStatusMaxRequest)
}
func DecodeNodePacketResult(r io.Reader) (NodePacketResult, error) {
	return nodeDecode[NodePacketResult](r, NodeCaptureMaxHeader)
}
