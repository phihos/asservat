package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
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
	return p.Composition.Valid() && len(p.Scope) > 0 && len(p.Scope) <= 64<<10 && p.Digest != (artifact.Digest{}) && len(p.Recipe) > 0 && p.RecipeDigest != (artifact.Digest{}) && p.Profile.DefinitionDigest != (artifact.Digest{}) && p.Action.Kind == "packetCapture" && p.Action.PacketProfile == "networkHeaders" && p.Action.ExecutionMode == "onTrigger" && p.Action.Before == "0s"
}
