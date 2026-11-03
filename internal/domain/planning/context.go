// Package planning contains immutable bounded plan values, never effect permits.
package planning

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

var ErrInvalid = errors.New("invalid or stale context plan")

// ContextCapability is a protected, qualified collection ceiling. Its revision
// identifies the exact accepted settings; enabled alone does not qualify an
// arbitrary collector or turn this value into execution authority.
type ContextCapability struct {
	ExecutionClass         artifact.ContextExecutionClass `json:",omitempty"`
	Revision               identity.Revision
	Enabled                bool
	CollectorVersion       string
	CollectorImageDigest   artifact.Digest
	ProjectionDigest       artifact.Digest
	ObservedAt, FreshUntil time.Time
}

func (c ContextCapability) Valid(now time.Time) bool {
	return c.ExecutionClass.Valid() && c.Enabled && c.Revision.Valid() && identity.Text(c.CollectorVersion, 64) && c.CollectorImageDigest != (artifact.Digest{}) && c.ProjectionDigest != (artifact.Digest{}) && identity.Fresh(c.ObservedAt, c.FreshUntil, now, 30*time.Second)
}

type ContextInput struct {
	CaptureID, CaseID string
	Executor          identity.Principal
	Deadline          time.Time
	Target            targets.PodResolution
	Retention         privacy.Resolution
	Capability        ContextCapability
	// Recorder selects an accepted node recorder plan (ADR-248) instead of
	// pod status: the authored composition with its filters frozen at
	// preview, so the plan never depends on a compiler being present later.
	Recorder *RecorderContext `json:",omitempty"`
	// Profile selects one finite Go endpoint acquisition with frozen resolution.
	Profile *ProfileContext `json:",omitempty"`
	// Snapshot selects one existing-source window, independently of finite recording.
	Snapshot *SourceSnapshotContext `json:",omitempty"`
	// SnapshotSource is a current exact-source observation, never persisted in passive preview.
	SnapshotSource *targets.SourceSnapshotResolution `json:",omitempty"`
}

// SourceSnapshotContext binds a saved window to its original policy executor
// and source definition. It cannot start or renew the separately owned source.
// RecordingSaveGroupBinding is immutable membership supplied by the protected
// parent preview/admission. It cannot select a replacement source or confer authority.
type RecordingSaveGroupBinding struct {
	ParentCaptureID        string
	SelectionDigest        artifact.Digest
	ChildIndex, ChildCount int
}

type SourceSnapshotContext struct {
	Group      *RecordingSaveGroupBinding `json:",omitzero"`
	PolicyName string                     `json:",omitempty"`
	// RecordingSaveScope is the immutable typed manual selection, independently
	// constructed before acceptance. Policy snapshots leave it empty.
	RecordingSaveScope               []byte          `json:",omitempty"`
	SourceDefinitionDigest           artifact.Digest `json:",omitzero"`
	Request                          artifact.SourceSnapshotRequest
	ActionID, PolicyUID, TriggerKind string
	// ActionKind is "syscallTrace" for a syscall source (ADR-273); empty is
	// the packet source, so existing packet plans keep their digests.
	ActionKind           string `json:",omitempty"`
	ExecutionDigest      artifact.Digest
	RecipeDigest         artifact.Digest
	SourceAudience       []artifact.AudienceAssignment
	SourceAudienceDigest artifact.Digest
	SourceTarget         *targets.SourceSnapshotTarget
}

func (s *SourceSnapshotContext) Clone() *SourceSnapshotContext {
	if s == nil {
		return nil
	}
	out := *s
	if s.Group != nil {
		group := *s.Group
		out.Group = &group
	}
	out.RecordingSaveScope = append(s.RecordingSaveScope[:0:0], s.RecordingSaveScope...)
	out.SourceAudience = append(s.SourceAudience[:0:0], s.SourceAudience...)
	if s.SourceTarget != nil {
		target := *s.SourceTarget
		out.SourceTarget = &target
	}
	return &out
}

// RecorderContext is the authored composition of a recorder capture and the
// hub-compiled programs of its filters, keyed by normalized expression.
type RecorderContext struct {
	Composition ProfileComposition
	Filters     []CompiledExpression `json:",omitempty"`
	Arguments   []CompiledArguments  `json:",omitempty"`
	// RequireApproval is the installation's ADR-249 switch as frozen in
	// the reviewed plan.
	RequireApproval bool `json:",omitempty"`
	// Peers are the frozen Kubernetes peer resolutions of the reviewed plan
	// (ADR-283 part 3), so acceptance recompiles the exact reviewed scope.
	Peers []targets.PeerResolution `json:",omitempty"`
}

// CompiledArguments is one release-qualified selection, frozen with approval.
type CompiledArguments struct {
	Names     []string
	Mechanism artifact.RecordingArguments
}

// CompiledExpression is one frozen filter compilation.
type CompiledExpression struct {
	Expression string
	Filter     CompiledFilter
}

// Clone returns an independent copy.
func (r *RecorderContext) Clone() *RecorderContext {
	if r == nil {
		return nil
	}
	out := RecorderContext{Composition: *r.Composition.Clone(), RequireApproval: r.RequireApproval}
	for _, a := range r.Arguments {
		a.Names = append([]string(nil), a.Names...)
		out.Arguments = append(out.Arguments, a)
	}
	for _, p := range r.Peers {
		out.Peers = append(out.Peers, p.Clone())
	}
	for _, f := range r.Filters {
		f.Filter.Program = append([]BPFInstruction(nil), f.Filter.Program...)
		out.Filters = append(out.Filters, f)
	}
	return &out
}

type ContextPlan struct {
	Input                     ContextInput
	CanonicalScope            []byte
	ScopeDigest, RecipeDigest artifact.Digest
	ValidUntil                time.Time
	CompiledAt                time.Time
}

// ProfileContext retains the reviewed endpoint and expanded binding inputs.
// It carries observations only; the region resolves them again before starting.
type ProfileContext struct {
	Composition     ProfileComposition
	Endpoints       []targets.ProfileEndpointResolution
	RequireApproval bool `json:",omitempty"`
}

func (p *ProfileContext) Clone() *ProfileContext {
	if p == nil {
		return nil
	}
	out := *p
	out.Composition = *p.Composition.Clone()
	out.Endpoints = make([]targets.ProfileEndpointResolution, len(p.Endpoints))
	for i, e := range p.Endpoints {
		out.Endpoints[i] = e.Clone()
	}
	return &out
}
