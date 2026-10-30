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
	// Snapshot selects one existing-source window, independently of finite recording.
	Snapshot *SourceSnapshotContext `json:",omitempty"`
	// SnapshotSource is a current exact-source observation, never persisted in passive preview.
	SnapshotSource *targets.SourceSnapshotResolution `json:",omitempty"`
}

// SourceSnapshotContext binds a saved window to its original policy executor
// and source definition. It cannot start or renew the separately owned source.
type SourceSnapshotContext struct {
	Request                          artifact.SourceSnapshotRequest
	ActionID, PolicyUID, TriggerKind string
	ExecutionDigest                  artifact.Digest
	RecipeDigest                     artifact.Digest
	SourceAudience                   []artifact.AudienceAssignment
	SourceAudienceDigest             artifact.Digest
	SourceTarget                     *targets.SourceSnapshotTarget
}

func (s *SourceSnapshotContext) Clone() *SourceSnapshotContext {
	if s == nil {
		return nil
	}
	out := *s
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
	// RequireApproval is the installation's ADR-249 switch as frozen in
	// the reviewed plan.
	RequireApproval bool `json:",omitempty"`
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
