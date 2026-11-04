package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	"slices"
	"time"
)

// PolicyRecorderConfiguration is target-independent normalized configuration.
// It contains no capture identity or concrete Pod. Scope/Digest freeze resolved
// profile definitions, typed edits, recipe bytes and compiled filter programs.
// Accepted policy authority adds the real workload and future-replica rules.
type PolicyRecorderConfiguration struct {
	Composition     ProfileComposition
	Profile         ResolvedProfile
	ProfileEndpoint *PolicyProfileEndpoint `json:",omitempty"`
	Action          RecorderAction
	Filter          *CompiledFilter
	Arguments       *artifact.RecordingArguments `json:",omitempty"`
	// SyscallInclude is a syscall source's sorted include list; empty
	// records every call (ADR-273).
	SyscallInclude       []string `json:",omitempty"`
	Recipe, Scope        []byte
	RecipeDigest, Digest artifact.Digest
}

func (p PolicyRecorderConfiguration) Valid() bool {
	profile := p.Action.Kind == "profile" && p.Action.ExecutionMode == "onTrigger" && p.Action.ProfileRuntime == "go" && p.Action.ProfileSource == "httpEndpoint" && p.Action.EndpointDigest == "" && p.ProfileEndpoint.Valid() && p.Arguments == nil && p.Filter == nil && len(p.SyscallInclude) == 0 && slices.Contains(p.Action.Sensitive, ReasonLiveProfile)
	if profile {
		d, err := time.ParseDuration(p.Action.Duration)
		if p.Action.Duration == "" {
			d, err = 0, nil
		}
		timeout, timeoutErr := time.ParseDuration(p.Action.Timeout)
		limit := artifact.MaxPprofBytes
		if p.Action.ProfileType == "runtimeTrace" {
			limit = artifact.MaxGoTraceBytes
		}
		profile = err == nil && timeoutErr == nil && artifact.ValidGoProfile(p.Action.ProfileType, p.Action.ProfileMode, d, p.Action.ForceGC) && timeout >= d+5*time.Second && timeout <= d+10*time.Second && p.Action.MaxBytes > 0 && p.Action.MaxBytes <= limit && p.Action.Before == "" && p.Action.After == ""
	}
	if p.ProfileEndpoint != nil && !profile {
		return false
	}
	arguments := p.Action.Kind == "syscallTrace" && p.Action.SyscallMode == "arguments" && p.Action.ExecutionMode == "onTrigger" && p.Filter == nil && p.Arguments.Valid() && slices.Contains(p.Action.Sensitive, ReasonSyscallArguments) && len(p.SyscallInclude) > 0 && len(p.SyscallInclude) <= 6 && slices.IsSorted(p.SyscallInclude)
	kind := p.Arguments == nil && (p.Action.Kind == "packetCapture" && p.Action.PacketProfile == "networkHeaders" && len(p.SyscallInclude) == 0 ||
		p.Action.Kind == "syscallTrace" && p.Action.SyscallMode == "metadata" && p.Action.ExecutionMode == "ongoing" && p.Filter == nil && len(p.SyscallInclude) <= 128 && slices.IsSorted(p.SyscallInclude)) || arguments
	lifecycle := p.Action.ExecutionMode == "onTrigger" && p.Action.Before == "0s"
	if arguments {
		after, err := time.ParseDuration(p.Action.After)
		lifecycle = lifecycle && err == nil && after >= time.Second && after <= time.Minute
	}
	if p.Action.ExecutionMode == "ongoing" {
		before, e := time.ParseDuration(p.Action.Before)
		after, e2 := time.ParseDuration(p.Action.After)
		age, e3 := time.ParseDuration(p.Action.RingMaxAge)
		lifecycle = e == nil && e2 == nil && e3 == nil && before >= 0 && after >= 0 && before+after > 0 && before <= age && age > 0 && age <= time.Hour && p.Action.RingMaxBytes > 0 && p.Action.RingMaxBytes <= 256<<20 && p.Action.SegmentBytes > 32 && p.Action.SegmentBytes <= 64<<20 && p.Action.MaxSegments >= 2 && p.Action.MaxSegments <= 64 && int64(p.Action.MaxSegments) <= p.Action.RingMaxBytes/p.Action.SegmentBytes && p.Action.MaxConcurrentSnapshots >= 1 && p.Action.MaxConcurrentSnapshots <= 4 && p.Action.MaxFrozenBytes > 0 && p.Action.MaxFrozenBytes <= 256<<20
	}
	return p.Composition.Valid() && len(p.Scope) > 0 && len(p.Scope) <= 64<<10 && p.Digest != (artifact.Digest{}) && len(p.Recipe) > 0 && p.RecipeDigest != (artifact.Digest{}) && p.Profile.DefinitionDigest != (artifact.Digest{}) && (kind && lifecycle || profile)
}
