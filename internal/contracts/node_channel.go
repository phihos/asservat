package contracts

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ADR-246: the private node work channel (I-02) between the `asservat node`
// DaemonSet and its cluster connector (docs/architecture/node-collector.md).
// The collector opens one long-lived HTTP/2 stream over server TLS and
// presents its audience-bound projected ServiceAccount token; the connector
// reviews it once per connection. Uploads are further requests on the same
// connection. No human credential, Kubernetes writer token, evidence or key
// material crosses this wire.
const (
	NodeDeploymentFormat   = "asservat-node-deployment/v1"
	NodeDeploymentRoot     = "/run/asservat/node"
	NodeDeploymentFile     = "node.json"
	NodeDeploymentMaxBytes = 64 << 10
	NodeTokenRoot          = "/run/asservat/node-token"
	NodeTokenFile          = "token"
	NodePodUIDEnvironment  = "ASSERVAT_NODE_POD_UID"
	// NodeDisposableHostGuard is the accidental-use barrier of the S-04 test
	// environment (plan §5.2): the collector refuses to start, and the chart's
	// hostPath of type File keeps the Pod from starting, unless the host
	// carries this file. Only disposable CI runners and VM images create it.
	NodeDisposableHostGuard = "/etc/asservat-disposable-host"
	// NodeRingDiskPath is the administrator\'s optional collector ring volume;
	// the encrypted-disk ring medium is available only while it is mounted (ADR-278).
	NodeRingDiskPath = "/var/lib/asservat-ring"

	// NodeConnectPath carries the stream: length-prefixed NodeUp frames from
	// the collector, length-prefixed NodeWork frames from the connector.
	NodeConnectPath    = "/internal/v1/node/connect"
	NodeChannelVersion = 1
	// NodeMaxMessage bounds one decoded control message: the largest typed
	// work item, a profile capture whose TLS bundle is bounded by its 1 MiB
	// ConfigMap, plus credential and envelope.
	NodeMaxMessage = 2 << 20

	// ADR-248: a finished packet capture travels node → connector as one
	// request: a 4-byte big-endian header length, the JSON NodePacketResult
	// header, then exactly CapturedBytes of PCAPNG.
	NodeCaptureFormat      = "asservat-node-capture/v1"
	NodeCapturePath        = "/internal/v1/node/capture"
	NodeCaptureContentType = "application/vnd.asservat.node-capture"
	NodeCaptureMaxHeader   = 4 << 10
)

var ErrNodeChannel = errors.New("node channel message rejected")

// NodeTokenAudience is the dedicated projected-token audience of the node
// collectors, a chart constant; only the cluster's own connector reviews it.
const NodeTokenAudience = "asservat-node"

// NodeConnectorRootFile is the collector's file, next to node.json, holding
// the connector listener's issuing root when node.json carries no rootsPEM.
// The connector publishes it into a Helm-rendered ConfigMap of the collector
// namespace (NodeListener).
const NodeConnectorRootFile = "connector-ca.crt"

// NodeDeployment is the collector's installation-owned public input, mounted
// from the chart's ConfigMap. Ceilings are the local administrator's
// collector-wide budgets (specs/capacity.md).
type NodeDeployment struct {
	Format    string                `json:"format"`
	Connector NodeConnectorEndpoint `json:"connector"`
	Ceilings  NodeCeilings          `json:"ceilings"`
	Live      *NodeLiveProcessing   `json:"live,omitempty"`
}

// NodeConnectorEndpoint pins the connector's node listener, the server name
// its certificate must carry and the roots that issued it.
type NodeLiveProcessing struct {
	Subscriptions            int   `json:"subscriptions"`
	MemoryBytes              int64 `json:"memoryBytes"`
	EventsPerSecond          int64 `json:"eventsPerSecond"`
	BytesPerSecond           int64 `json:"bytesPerSecond"`
	ProcessingNanosPerSecond int64 `json:"processingNanosPerSecond"`
}

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
	// RingDiskBytes is the administrator's ring volume size (ADR-278); zero
	// without the volume.
	RingDiskBytes int64 `json:"ringDiskBytes,omitempty"`
}

// NodeHello is the first message of a stream: the protocol version and the
// work kinds this collector handles. The connector sends no other kind.
type NodeHello struct {
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// NodeUp is one collector → connector message.
type NodeUp struct {
	Hello  *NodeHello  `json:"hello,omitempty"`
	Status *NodeStatus `json:"status,omitempty"`
}

// NodeWork is one closed work item: armSource, stopSource, snapshot,
// peerGeneration or packetCapture. Only packetCapture (ADR-248) carries a
// typed payload in this version; the others carry only their identity.
type NodeLiveRead struct {
	Manual           *NodeManualLiveSource `json:"manual,omitempty"`
	Inspect          bool                  `json:"inspect,omitempty"`
	ReplyBytes       int                   `json:"replyBytes"`
	WaitMS           int                   `json:"waitMS"`
	Binding          NodeSourceBinding     `json:"binding"`
	ClusterID        string                `json:"clusterID"`
	NamespaceUID     string                `json:"namespaceUID"`
	WorkloadUID      string                `json:"workloadUID"`
	Projection       string                `json:"projection"`
	PrivacyUntil     time.Time             `json:"privacyUntil"`
	Generation       int64                 `json:"generation"`
	AfterSequence    uint64                `json:"afterSequence"`
	AfterLost        uint64                `json:"afterLost"`
	AfterClockLost   uint64                `json:"afterClockLost,omitempty"`
	AfterUnsupported uint64                `json:"afterUnsupported,omitempty"`
	AfterSensorLost  uint64                `json:"afterSensorLost,omitempty"`
	Head             bool                  `json:"head"`
	Limit            int                   `json:"limit"`
}

type NodeWork struct {
	Live                 *NodeLiveRead       `json:"live,omitempty"`
	ID                   string              `json:"id"`
	Sequence             uint64              `json:"sequence"`
	Kind                 string              `json:"kind"`
	NotAfter             time.Time           `json:"notAfter"`
	ProfileCapture       *NodeProfileCapture `json:"profileCapture,omitempty"`
	CancelProfileCapture *NodePacketCancel   `json:"cancelProfileCapture,omitempty"`
	PacketCapture        *NodePacketCapture  `json:"packetCapture,omitempty"`
	PacketSource         *NodePacketSource   `json:"packetSource,omitempty"`
	CancelSourceSnapshot *NodeSourceSnapshot `json:"cancelSourceSnapshot,omitempty"`
	SourceSnapshot       *NodeSourceSnapshot `json:"sourceSnapshot,omitempty"`
	StopPacketSource     *NodeSourceBinding  `json:"stopPacketSource,omitempty"`
	CancelPacketCapture  *NodePacketCancel   `json:"cancelPacketCapture,omitempty"`
}

// NodePacketCancel names one running finite packetCapture item to stop early
// (ADR-283): its capture ID and the ID of the work item that started it.
type NodePacketCancel struct {
	CaptureID string `json:"captureID"`
	WorkID    string `json:"workID"`
}

// NodePacketSource is a distinct ordinary ongoing work purpose. Older nodes
// reject these fields/kinds rather than interpreting them as a finite capture.
type NodePacketSource struct {
	HTTP              *NodeHTTPProjection  `json:"http,omitempty"`
	Permit            NodeSourcePermit     `json:"permit"`
	Program           []NodeBPFInstruction `json:"program"`
	Ring              NodeSourceRingLimits `json:"ring"`
	ResourcePolicyUID string               `json:"resourcePolicyUID"`
	NodeLimits        NodeCeilings         `json:"nodeLimits"`
	WorkloadLimits    NodeSourceLimits     `json:"workloadLimits"`
	// Syscalls makes this a syscall metadata source (ADR-273).
	Syscalls *NodeSyscallFilter `json:"syscalls,omitempty"`
}
type NodeSyscallFilter struct {
	Names             []string `json:"names"`
	ErrorsOnly        bool     `json:"errorsOnly,omitempty"`
	MaxEvents         int64    `json:"maxEvents"`
	MaxTrackedThreads int64    `json:"maxTrackedThreads"`
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
	ObservationGrantID string `json:"observationGrantID,omitempty"`
	AudienceDigest     string `json:"audienceDigest,omitempty"`
	RootID             string `json:"rootID"`
	PolicyUID          string `json:"policyUID"`
	AcceptanceID       string `json:"acceptanceID"`
	SourceID           string `json:"sourceID"`
	Fence              string `json:"fence"`
	ActionID           string `json:"actionID"`
	PodUID             string `json:"podUID"`
	NodeUID            string `json:"nodeUID"`
	BootID             string `json:"bootID"`
	CollectorPodUID    string `json:"collectorPodUID"`
	CollectorEpoch     string `json:"collectorEpoch"`
	Scope              string `json:"scope"`
	ExpectationDigest  string `json:"expectationDigest"`
	ProgramDigest      string `json:"programDigest"`
	ResourceDigest     string `json:"resourceDigest"`
}
type NodeSourceRingLimits struct {
	MaxAgeNanos            int64 `json:"maxAgeNanos"`
	MaxBytes               int64 `json:"maxBytes"`
	SegmentBytes           int64 `json:"segmentBytes"`
	MaxFrozenBytes         int64 `json:"maxFrozenBytes"`
	MaxSegments            int   `json:"maxSegments"`
	MaxConcurrentSnapshots int   `json:"maxConcurrentSnapshots"`
	EncryptedDisk          bool  `json:"encryptedDisk,omitempty"`
}

// NodePacketCapture is one manual networkHeaders capture of one Pod. Program
// is the hub-compiled classic BPF program (empty: all traffic) and
// ProgramDigest its SHA-256 over little-endian struct sock_filter bytes in
// lowercase hex (empty with an empty program).
type NodePacketCapture struct {
	CaptureID      string                         `json:"captureID"`
	PodUID         string                         `json:"podUID"`
	Program        []NodeBPFInstruction           `json:"program"`
	ProgramDigest  string                         `json:"programDigest"`
	DurationMillis int64                          `json:"durationMillis"`
	MaxBytes       int64                          `json:"maxBytes"`
	Observation    *NodeObservationPermit         `json:"observation,omitempty"`
	Arguments      *NodeArgumentObservationPermit `json:"arguments,omitempty"`
	// Syscalls and MaxEventsPerSecond make this a finite syscall metadata
	// recording (B3, work kind syscallCapture).
	Syscalls           *NodeSyscallFilter `json:"syscalls,omitempty"`
	MaxEventsPerSecond int64              `json:"maxEventsPerSecond,omitempty"`
	// Raw keeps payload prefixes of an observed rawPackets recording
	// (ADR-279): snaplen, or a nonzero per-transport cap instead.
	Raw *NodeRawPrefix `json:"raw,omitempty"`
	// HTTP projects plain HTTP/1 headers of an observed httpHeaders
	// recording (ADR-282) from frames read at raw's fixed snaplen.
	HTTP *NodeHTTPProjection `json:"http,omitempty"`
}

// NodeHTTPProjection are the parser bounds of an httpHeaders recording.
type NodeHTTPProjection struct {
	MaxFlows          int   `json:"maxFlows"`
	MaxHeaderBytes    int   `json:"maxHeaderBytes"`
	MaxFlowBytes      int   `json:"maxFlowBytes"`
	MaxTotalBytes     int   `json:"maxTotalBytes"`
	IdleTimeoutMillis int64 `json:"idleTimeoutMillis"`
}

type NodeRawPrefix struct {
	Snaplen int `json:"snaplen"`
	TCP     int `json:"tcp,omitempty"`
	UDP     int `json:"udp,omitempty"`
	ICMP    int `json:"icmp,omitempty"`
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
	NativeType    string               `json:"nativeType,omitempty"`
	Failure       string               `json:"failure"`
}

// NodeStatus is one report: probed facts, mechanism assessment, node budget
// usage and receipts for work handled since the previous report.
type NodeStatus struct {
	ObservedAt time.Time          `json:"observedAt"`
	Probe      NodeProbe          `json:"probe"`
	Mechanisms []NodeAdapter      `json:"mechanisms"`
	Budget     NodeBudget         `json:"budget"`
	Receipts   []NodeReceipt      `json:"receipts"`
	Sources    []NodeSourceStatus `json:"sources,omitempty"`
	Live       *NodeLiveStatus    `json:"live,omitempty"`
}

type NodeLiveStatus struct {
	WindowStartedAt   time.Time `json:"windowStartedAt,omitzero"`
	Cohorts           int       `json:"cohorts"`
	ScanEvents        int64     `json:"scanEvents"`
	ScanBytes         int64     `json:"scanBytes"`
	ScanCPUNanos      int64     `json:"scanCPUNanos"`
	DeliveredRows     int64     `json:"deliveredRows"`
	DeliveredBytes    int64     `json:"deliveredBytes"`
	RefusedAdmissions int64     `json:"refusedAdmissions"`
	LostEvents        int64     `json:"lostEvents"`
	DroppedRows       int64     `json:"droppedRows"`
	PendingRows       int       `json:"pendingRows"`
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
	Mechanism            string   `json:"mechanism"`
	Prerequisites        bool     `json:"prerequisites"`
	Adapter              string   `json:"adapter"`
	Hook                 string   `json:"hook"`
	Reasons              []string `json:"reasons"`
	ProfileTLS           bool     `json:"profileTLS,omitempty"`
	ProfileAuthorization bool     `json:"profileAuthorization,omitempty"`
	LiveProjections      []string `json:"liveProjections,omitempty"`
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

// nodeDecode reads one bounded JSON value. Unknown fields are ignored, so
// collectors and connectors one version apart interoperate.
func nodeDecode[T any](r io.Reader, limit int64) (T, error) {
	var out T
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	defer clear(b)
	if err != nil || int64(len(b)) > limit || json.Unmarshal(b, &out) != nil {
		var zero T
		return zero, ErrNodeChannel
	}
	return out, nil
}

// WriteNodeFrame writes one length-prefixed JSON message.
func WriteNodeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	defer clear(b)
	if err != nil || len(b) > NodeMaxMessage {
		return ErrNodeChannel
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	if _, err = w.Write(size[:]); err == nil {
		_, err = w.Write(b)
	}
	return err
}

// ReadNodeFrame reads one length-prefixed JSON message of at most
// NodeMaxMessage bytes.
func ReadNodeFrame[T any](r io.Reader) (T, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		var zero T
		return zero, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > NodeMaxMessage {
		var zero T
		return zero, ErrNodeChannel
	}
	return nodeDecode[T](io.LimitReader(r, int64(n)), int64(n))
}

func DecodeNodeDeployment(r io.Reader) (NodeDeployment, error) {
	return nodeDecode[NodeDeployment](r, NodeDeploymentMaxBytes)
}
func DecodeNodePacketResult(r io.Reader) (NodePacketResult, error) {
	return nodeDecode[NodePacketResult](r, NodeCaptureMaxHeader)
}
