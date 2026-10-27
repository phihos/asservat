package planning

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// Refusal codes of a composition preview (ADR-243). Each is reported with the
// authored field path and a remedy; none reserves work or reaches a target.
const (
	CompositionInvalid        = "InvalidComposition"
	CompositionProfileMissing = "ProfileUnavailable"
	CompositionFilterRejected = "FilterRejected"
	CompositionApproval       = "ApprovalRequired"
	CompositionNoCompiler     = "FilterCompilerUnavailable"
)

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
}

// RecorderAction is the normalized review summary of one expanded action.
type RecorderAction struct {
	ID, ComponentID, LocalID, Kind, ExecutionMode, EvidenceType string
	Before, After, Timeout, RingMaxAge                          string
	RingMaxBytes, SegmentBytes, MaxFrozenBytes, MaxBytes        int64
	MaxSegments, MaxConcurrentSnapshots                         int
	// Packet actions.
	PacketProfile, Filter string
	FilterInstructions    int
	FilterDigest          artifact.Digest
	// Syscall actions.
	SyscallMode, SyscallSelection, Result            string
	SyscallNames                                     int
	MaxEvents, MaxEventsPerSecond, MaxTrackedThreads int64
}

// ResolvedProfile pins one embedded builtin definition by digest (S6).
type ResolvedProfile struct {
	ComponentID      string
	Ref              ProfileRef
	DefinitionDigest artifact.Digest
}

// RecorderPlan is a compiled, reviewable packet/syscall plan. It is not an
// accepted execution scope: no node recorder exists to accept it (ADR-243).
type RecorderPlan struct {
	Input          RecorderInput
	Actions        []RecorderAction
	Profiles       []ResolvedProfile
	RecipeDigest   artifact.Digest
	CanonicalScope []byte
	ScopeDigest    artifact.Digest
	CompiledAt     time.Time
	ValidUntil     time.Time
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
