package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	"time"
)

// PolicyRecorderConfiguration is target-independent normalized configuration.
// It contains no capture identity or concrete Pod. Scope/Digest freeze resolved
// profile definitions, typed edits, recipe bytes and compiled filter programs.
// Accepted policy authority adds the real workload and future-replica rules.
type PolicyRecorderConfiguration struct {
	Composition          ProfileComposition
	Profile              ResolvedProfile
	Action               RecorderAction
	Filter               *CompiledFilter
	Recipe, Scope        []byte
	RecipeDigest, Digest artifact.Digest
}

func (p PolicyRecorderConfiguration) Valid() bool {
	lifecycle := p.Action.ExecutionMode == "onTrigger" && p.Action.Before == "0s"
	if p.Action.ExecutionMode == "ongoing" {
		before, e := time.ParseDuration(p.Action.Before)
		after, e2 := time.ParseDuration(p.Action.After)
		age, e3 := time.ParseDuration(p.Action.RingMaxAge)
		lifecycle = e == nil && e2 == nil && e3 == nil && before >= 0 && after >= 0 && before+after > 0 && before <= age && age > 0 && age <= time.Hour && p.Action.RingMaxBytes > 0 && p.Action.RingMaxBytes <= 256<<20 && p.Action.SegmentBytes > 32 && p.Action.SegmentBytes <= 64<<20 && p.Action.MaxSegments >= 2 && p.Action.MaxSegments <= 64 && int64(p.Action.MaxSegments) <= p.Action.RingMaxBytes/p.Action.SegmentBytes && p.Action.MaxConcurrentSnapshots >= 1 && p.Action.MaxConcurrentSnapshots <= 4 && p.Action.MaxFrozenBytes > 0 && p.Action.MaxFrozenBytes <= 256<<20
	}
	return p.Composition.Valid() && len(p.Scope) > 0 && len(p.Scope) <= 64<<10 && p.Digest != (artifact.Digest{}) && len(p.Recipe) > 0 && p.RecipeDigest != (artifact.Digest{}) && p.Profile.DefinitionDigest != (artifact.Digest{}) && p.Action.Kind == "packetCapture" && p.Action.PacketProfile == "networkHeaders" && lifecycle
}
