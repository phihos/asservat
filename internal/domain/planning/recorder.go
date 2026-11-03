package planning

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Refusal codes of a composition preview (ADR-243). Each is reported with the
// authored field path and a remedy; none reserves work or reaches a target.
const (
	CompositionInvalid             = "InvalidComposition"
	CompositionProfileMissing      = "ProfileUnavailable"
	CompositionFilterRejected      = "FilterRejected"
	CompositionApproval            = "ApprovalRequired"
	CompositionNoCompiler          = "FilterCompilerUnavailable"
	CompositionRecorderUnavailable = "RecorderUnavailable"
	// CompositionConflict is a duplicate or overlapping acquisition (REQ-CPR-003).
	CompositionConflict = "AcquisitionConflict"
	// CompositionPeersChanged is a frozen Kubernetes peer set that no longer
	// resolves to the reviewed members at submission (ADR-283 part 3).
	CompositionPeersChanged = "PeerMembershipChanged"
	// CompositionEndpointAmbiguous and CompositionEndpointDenied refuse a Go
	// profile endpoint that resolves ambiguously or outside its template
	// (REQ-PRF-001, ADR-285).
	CompositionEndpointAmbiguous = "EndpointAmbiguous"
	CompositionEndpointDenied    = "EndpointDenied"
)

// Sensitive-acquisition reasons (ADR-249). Either makes the plan need an
// individual approval before anything is armed.
const (
	// ReasonRawBytePredicate: a proto[offset] filter can test payload bytes.
	ReasonRawBytePredicate = "rawBytePredicate"
	// ReasonRawPackets: the recording keeps payload prefixes (ADR-279).
	ReasonRawPackets = "rawPackets"
	// ReasonHTTPHeaders: acquisition reads payload to project HTTP/1 headers
	// (ADR-282); the output is an extract.
	ReasonHTTPHeaders      = "httpHeaders"
	ReasonSyscallArguments = "syscallArguments"
	// ReasonLiveProfile: live profiling is intrusive for approval purposes
	// even when the mechanism is an HTTP GET (REQ-PRF-002, ADR-285).
	ReasonLiveProfile = "liveProfile"
	// ReasonRecordingApproval: the installation requires approval for every
	// packet/syscall recording (REQ-SYS-002 "unless an administrator requires more").
	ReasonRecordingApproval = "recordingApprovalRequired"
	// Fixed observation limits of a manual raw-byte predicate plan
	// (REQ-AUT-006): cumulative bytes entering the predicate and its rate.
	SensitiveMaxObservedBytes  = int64(1) << 30
	SensitiveMaxBytesPerSecond = int64(16) << 20
)

// ObservationLimits are REQ-AUT-006 limits bound into the plan.
type ObservationLimits struct {
	// Omitted on legacy packet scopes; zero never authorizes argument probes.
	MaxObservedEvents                                                             int64 `json:",omitempty"`
	MaxSessionSeconds, MaxObservedBytes, MaxBytesPerSecond, MaxConcurrentSessions int64
}

// RecorderApproval is a plan's requirement for an individual approval.
type RecorderApproval struct {
	DataClass         string
	Reasons           []authorization.SensitiveReason
	ObservationLimits *ObservationLimits
}

// CompositionError is a field-level refusal of an authored composition.
type CompositionError struct {
	Code, Path, Reason string
}

func (e CompositionError) Error() string { return e.Code + " at " + e.Path + ": " + e.Reason }

// ErrFilterCompilerUnavailable is returned by a hub build without the
// statically linked libpcap compiler (build tag libpcap).
var ErrFilterCompilerUnavailable = errors.New("packet filter compiler unavailable")

// Pinned filter compilation profile (S2): Ethernet link type and the snapshot
// length of the qualified feasibility corpus. The node never compiles.
const (
	FilterLinkType         = "EN10MB"
	FilterSnaplen          = 65535
	MaxFilterBytes         = 4096
	MaxFilterTokens        = 256
	MaxFilterInstructions  = 256
	FilterProgramEncoding  = "pcap-cbpf/v1"
	RecorderPlanVersion    = "recorder-preview/v1"
	RecorderAssessmentRule = "recorder-assessment/v1"
)

// BPFInstruction is one classic BPF instruction (struct sock_filter).
type BPFInstruction struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// CompiledFilter is the libpcap output for one normalized expression.
type CompiledFilter struct {
	LinkType string
	Snaplen  int
	Program  []BPFInstruction
}

// RecorderInput contains only independently resolved facts. Authored text such
// as a filter is compiled; it never selects the target, executor or retention.
type RecorderInput struct {
	CaptureID   string
	Executor    identity.Principal
	Target      targets.PodResolution
	Composition ProfileComposition
	Retention   privacy.Resolution
	Deadline    time.Time
	// RequireApproval is the protected installation setting that every
	// recording needs approval (ADR-249); never a caller option.
	RequireApproval bool
	// NodeRecorder marks a plan whose target's node collector reported the
	// packet recorder at preview (ADR-248): acceptance "nodeRecorder" instead
	// of the interim "recorderUnavailable". It enters the plan digest.
	NodeRecorder bool `json:",omitempty"`
	// Peers are the region's Kubernetes peer resolutions this plan was
	// compiled with (ADR-283 PR 2), one per action with Kubernetes peers.
	// They are observations frozen for review, never authority.
	Peers []targets.PeerResolution `json:",omitempty"`
	// Endpoints are the region's Go profile endpoint resolutions this plan
	// was compiled with (ADR-285), one per httpEndpoint profile action:
	// observations frozen for review, never authority.
	Endpoints []targets.ProfileEndpointResolution `json:",omitempty"`
}

// RecorderAction is the normalized review summary of one expanded action.
type RecorderAction struct {
	ID, ComponentID, LocalID, Kind, ExecutionMode, EvidenceType string
	Before, After, Timeout, RingMaxAge                          string
	RingMaxBytes, SegmentBytes, MaxFrozenBytes, MaxBytes        int64
	MaxSegments, MaxConcurrentSnapshots                         int
	// RingMedium is "encryptedDisk" for that medium (ADR-278) and empty for
	// memory, so existing memory plans serialize exactly as before.
	RingMedium string `json:",omitempty"`
	// Packet actions.
	PacketProfile, Filter string
	FilterInstructions    int
	FilterDigest          artifact.Digest
	// PeerPrefixes counts the CIDR peer prefixes intersected into Filter
	// (ADR-283); zero selects all pod traffic.
	PeerPrefixes int `json:",omitempty"`
	// PeerEndpoints counts the resolved Kubernetes peer members (UID, IP)
	// and PeerMembersDigest is their digest (hex); zero without Kubernetes
	// peers.
	PeerEndpoints     int    `json:",omitempty"`
	PeerMembersDigest string `json:",omitempty"`
	// Syscall actions.
	SyscallMode, SyscallSelection, Result            string
	SyscallNames                                     int
	MaxEvents, MaxEventsPerSecond, MaxTrackedThreads int64
	// Profile actions (ADR-285): runtime, type, mode, the timed duration
	// (empty for snapshots and cumulative counters), source kind, forced GC
	// and the resolved endpoint digest (hex, Go endpoints only).
	ProfileRuntime string `json:",omitempty"`
	ProfileType    string `json:",omitempty"`
	ProfileMode    string `json:",omitempty"`
	ProfileSource  string `json:",omitempty"`
	Duration       string `json:",omitempty"`
	ForceGC        bool   `json:",omitempty"`
	EndpointDigest string `json:",omitempty"`
	// Sensitive lists the action's approval reason codes (ADR-249).
	Sensitive []string
}

// ResolvedProfile pins one embedded builtin definition by digest (S6).
type ResolvedProfile struct {
	ComponentID      string
	Ref              ProfileRef
	DefinitionDigest artifact.Digest
	// Catalog (non-builtin) versions name their source (REQ-CPR-001).
	SourceClusterID, SourceNamespaceUID, SourceUID string `json:",omitempty"`
	// Deprecated versions stay usable but are visibly discouraged.
	Deprecated bool `json:",omitempty"`
}

// RecorderPlan is a compiled, reviewable packet/syscall plan (ADR-243). Only a
// manual networkHeaders plan compiled for an available node recorder can be
// accepted, through the context plan (ADR-248).
type RecorderPlan struct {
	Input          RecorderInput
	Actions        []RecorderAction
	Profiles       []ResolvedProfile
	RecipeDigest   artifact.Digest
	CanonicalScope []byte
	ScopeDigest    artifact.Digest
	CompiledAt     time.Time
	ValidUntil     time.Time
	// Approval is non-nil when the plan needs an individual approval.
	Approval *RecorderApproval
}

// AssessmentQuantity is a typed configured limit; never a measurement here.
type AssessmentQuantity struct {
	Dimension, Phase, Scope, Basis, SourceRef, Coverage string
	Lower, Upper                                        int64
}

type RecorderActionAssessment struct {
	ActionID, ExecutionMode string
	Impact                  AssessmentImpact
	Exposure                AssessmentExposure
	Retention               AssessmentRetention
	Quantities              []AssessmentQuantity
}

type AssessmentAlternative struct {
	ActionIDs                     []string
	Change, Benefit, CoverageLoss string
}

// RecorderAssessment is the deterministic capture-assessment/v1 projection of
// a recorder plan. It grants no authority and contains no measured overhead.
type RecorderAssessment struct {
	ID                                        string
	PlanDigest, RulesDigest, CapabilityDigest artifact.Digest
	GeneratedAt, ValidUntil                   time.Time
	ObservationPods, IncidentPods             int
	Combined                                  AssessmentImpact
	Actions                                   []RecorderActionAssessment
	CombinedQuantities                        []AssessmentQuantity
	Alternatives                              []AssessmentAlternative
	Interaction                               string
}
