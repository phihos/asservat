package planning

import (
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
)

// The reviewed recorder rules (specs/capture-assessment.md REQ-ASM-001–004).
// They name known effects and conservative data categories; every quantity is
// a configured limit, never a measured or estimated overhead. A change to an
// effect, category or interpretation requires a new rule digest.
const (
	packetAssessmentRule  = `{"rule":"recorder-assessment/v2","mechanism":"packetCapture","profile":"networkHeaders","impact":"unknown","effects":["nodeCPU","collectorMemory","storageIO","uploadContention"],"retained":["networkAddresses","personalIdentifiers"],"transient":["userContent","credentials"],"anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident","ring:whileArmed|perIncident","frozen:perIncident"]}`
	syscallAssessmentRule = `{"rule":"recorder-assessment/v2","mechanism":"syscallTrace","mode":"metadata","impact":"unknown","effects":["nodeCPU","applicationCPU","collectorMemory","storageIO","uploadContention"],"retained":["personalIdentifiers"],"transient":[],"anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident","ring:whileArmed|perIncident","frozen:perIncident"]}`
	// No recorder capability exists in this release; the basis names that fact.
	recorderCapabilityAbsent = "recorder-capability/v1:unavailable"
)

// RecorderAssessmentRulesDigest pins both mechanism rules.
func RecorderAssessmentRulesDigest() artifact.Digest {
	return artifact.Digest(sha256.Sum256([]byte(packetAssessmentRule + "\n" + syscallAssessmentRule)))
}

// RecorderCapabilityDigest identifies the absent recorder capability basis.
func RecorderCapabilityDigest() artifact.Digest {
	return artifact.Digest(sha256.Sum256([]byte(recorderCapabilityAbsent)))
}

const (
	outputCoverage = "Configured acquired output bytes; excludes encryption/object overhead, replication and temporary copies; not expected size."
	ringCoverage   = "Declared memory ring; excludes kernel maps, collector baseline, encryption and frozen copies."
	frozenCoverage = "Declared frozen snapshot buffers; excludes the continuing ring, collector baseline, encryption and upload staging."
)

func quantity(dimension, phase, scope, source, coverage string, upper int64) value.AssessmentQuantity {
	return value.AssessmentQuantity{Dimension: dimension, Phase: phase, Scope: scope, Basis: "configuredLimit", SourceRef: source, Coverage: coverage, Upper: upper}
}

// AssessRecorder performs no I/O or trial acquisition. Authorization belongs to
// the caller; this must not disclose a target to an ineligible requester. The
// combined level is never below a component's; unknown stays unknown.
func AssessRecorder(plan value.RecorderPlan, assessmentID string, now time.Time) (value.RecorderAssessment, error) {
	if !authorization.UUID(assessmentID) || len(plan.Actions) < 1 || len(plan.CanonicalScope) == 0 || now.Before(plan.CompiledAt) || !now.Before(plan.ValidUntil) {
		return value.RecorderAssessment{}, value.ErrInvalid
	}
	r := plan.Input.Retention
	digests := []artifact.Digest{}
	seen := map[artifact.Digest]bool{}
	for _, p := range r.Policies {
		if !seen[p.Digest] {
			digests = append(digests, p.Digest)
			seen[p.Digest] = true
		}
	}
	retention := value.AssessmentRetention{
		AccessAgeSeconds: int64(r.ExpiresAt.Sub(r.AnchorAt) / time.Second), DeleteAgeSeconds: int64(r.DeleteBy.Sub(r.AnchorAt) / time.Second),
		MaximumAgeSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, PolicyDigests: digests,
	}
	out := value.RecorderAssessment{
		ID: assessmentID, PlanDigest: plan.ScopeDigest, RulesDigest: RecorderAssessmentRulesDigest(), CapabilityDigest: RecorderCapabilityDigest(),
		GeneratedAt: now, ValidUntil: plan.ValidUntil, IncidentPods: 1,
		Combined:    value.AssessmentImpact{Level: "unknown", HasUnknowns: true, Explanation: "Recorder overhead depends on traffic, call rate and placement and is not measured; no recorder runs in this release. Limits are not predictions."},
		Interaction: "Current node and upload pressure and other recorders on the same node are not measured by this preview.",
	}
	if plan.Input.NodeRecorder {
		out.Combined.Explanation = "Recorder overhead depends on traffic and placement and is not measured by this preview. This manual capture runs on the target node's collector and saves at most 8 MiB. Limits are not predictions."
	}
	var ringArmed, ringIncident, frozen, output int64
	effects := map[string]bool{}
	for _, a := range plan.Actions {
		assessed := value.RecorderActionAssessment{ActionID: a.ID, ExecutionMode: a.ExecutionMode, Retention: retention}
		assessed.Retention.PolicyDigests = append([]artifact.Digest(nil), digests...)
		ringPhase, ringScope := "perIncident", "perIncidentPod"
		if a.ExecutionMode == "ongoing" {
			ringPhase, ringScope = "whileArmed", "perObservationPod"
			out.ObservationPods = 1
			ringArmed += a.RingMaxBytes
		} else {
			ringIncident += a.RingMaxBytes
		}
		frozen += a.MaxFrozenBytes
		limit := a.MaxBytes
		if plan.Input.NodeRecorder && a.Kind == "packetCapture" {
			limit = min(limit, artifact.RecordingNativeLimit) // ADR-248 interim cap
		}
		output += limit
		switch a.Kind {
		case "packetCapture":
			assessed.Impact = value.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"nodeCPU", "collectorMemory", "storageIO", "uploadContention"},
				Explanation: "Kernel packet hooks add per-packet node work and the ring holds headers in collector memory; overhead depends on traffic and is not measured. Limits bound retained data, not latency."}
			assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"networkAddresses", "personalIdentifiers"}, TransientOnly: []string{"userContent", "credentials"}}
			if a.Filter == "" {
				out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "narrowScope", Benefit: "A pcap filter on hosts or ports reduces node work and retained addresses.", CoverageLoss: "Traffic outside the filter is not recorded."})
			}
		case "syscallTrace":
			assessed.Impact = value.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"nodeCPU", "applicationCPU", "collectorMemory", "storageIO", "uploadContention"},
				Explanation: "Kernel probes run on every system call of every pod process; event rate and probe cost are not measured. Limits bound retained events, not application latency."}
			assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"personalIdentifiers"}, TransientOnly: []string{}}
			if a.SyscallSelection == "all" {
				out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "narrowScope", Benefit: "Selected syscall names reduce probe work and retained events.", CoverageLoss: "Calls outside the selection are not recorded."})
			}
		default:
			return value.RecorderAssessment{}, value.ErrInvalid
		}
		if a.ExecutionMode == "ongoing" && a.Before != "0s" {
			out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "futureOnly", Benefit: "On trigger with before 0s records only the next interval and states that no history exists.", CoverageLoss: "No traffic or calls before the request; a manual recording has none anyway."})
		}
		for _, e := range assessed.Impact.Effects {
			effects[e] = true
		}
		assessed.Quantities = []value.AssessmentQuantity{
			quantity("outputBytes", "perIncident", "perIncidentPod", "action:"+a.ID+":maxBytes", outputCoverage, limit),
			quantity("collectorMemoryBytes", ringPhase, ringScope, "action:"+a.ID+":ring.maxBytes", ringCoverage, a.RingMaxBytes),
			quantity("collectorMemoryBytes", "perIncident", "perIncidentPod", "action:"+a.ID+":maxFrozenBytes", frozenCoverage, a.MaxFrozenBytes),
		}
		out.Actions = append(out.Actions, assessed)
	}
	for _, e := range []string{"applicationCPU", "nodeCPU", "collectorMemory", "storageIO", "uploadContention"} {
		if effects[e] {
			out.Combined.Effects = append(out.Combined.Effects, e)
		}
	}
	if ringArmed > 0 {
		out.CombinedQuantities = append(out.CombinedQuantities, quantity("collectorMemoryBytes", "whileArmed", "wholePlan", "sum-of-declared-ring-limits", ringCoverage, ringArmed))
	}
	out.CombinedQuantities = append(out.CombinedQuantities, quantity("collectorMemoryBytes", "perIncident", "wholePlan", "sum-of-declared-frozen-and-staging-limits", frozenCoverage, frozen+ringIncident))
	out.CombinedQuantities = append(out.CombinedQuantities, quantity("outputBytes", "perIncident", "wholePlan", "sum-of-declared-output-limits", outputCoverage, output))
	if len(out.Alternatives) > 8 {
		out.Alternatives = out.Alternatives[:8]
	}
	return out, nil
}
