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
}
type ContextPlan struct {
	Input                     ContextInput
	CanonicalScope            []byte
	ScopeDigest, RecipeDigest artifact.Digest
	ValidUntil                time.Time
	CompiledAt                time.Time
}
