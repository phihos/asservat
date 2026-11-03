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
	rawAssessmentRule     = `{"rule":"recorder-assessment/v2","mechanism":"packetCapture","profile":"rawPackets","impact":"unknown","effects":["nodeCPU","collectorMemory","storageIO","uploadContention"],"retained":["networkAddresses","personalIdentifiers","userContent","credentials"],"transient":[],"caps":"byteBudgetNotRedaction","anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident","frozen:perIncident"]}`
	httpAssessmentRule    = `{"rule":"recorder-assessment/v2","mechanism":"packetCapture","profile":"httpHeaders","impact":"unknown","effects":["nodeCPU","collectorMemory","storageIO","uploadContention"],"retained":["personalIdentifiers"],"transient":["userContent","credentials","networkAddresses"],"projection":"http-response-headers/v1","anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident","frozen:perIncident"]}`
	syscallAssessmentRule = `{"rule":"recorder-assessment/v2","mechanism":"syscallTrace","mode":"metadata","impact":"unknown","effects":["nodeCPU","applicationCPU","collectorMemory","storageIO","uploadContention"],"retained":["personalIdentifiers"],"transient":[],"anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident","ring:whileArmed|perIncident","frozen:perIncident"]}`
	// ADR-285: Go endpoint profiles run in the application; the eBPF CPU
	// sampler samples the node host-wide during its session and keeps only
	// the selected Pod's samples. Effects are known minimums, never measured.
	goProfileAssessmentRule      = `{"rule":"recorder-assessment/v2","mechanism":"profile","source":"httpEndpoint","runtime":"go","impact":"moderate","unknowns":true,"effects":["applicationCPU","applicationAllocation"],"forceGC":["forcedGC","applicationPause"],"retained":["paths","profileLabels","personalIdentifiers"],"runtimeTrace":["unknownApplicationData"],"transient":[],"anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident"]}`
	samplerProfileAssessmentRule = `{"rule":"recorder-assessment/v2","mechanism":"profile","source":"ebpfSampler","runtime":"any","impact":"unknown","effects":["nodeCPU","collectorMemory"],"scope":"hostWideSamplingDuringSession","retained":["paths"],"transient":["personalIdentifiers"],"anchor":"submissionPreparation","metrics":"unavailable","quantities":["outputBytes:perIncident"]}`
	// No recorder capability exists in this release; the basis names that fact.
	recorderCapabilityAbsent = "recorder-capability/v1:unavailable"
)

// RecorderAssessmentRulesDigest pins both mechanism rules.
func RecorderAssessmentRulesDigest() artifact.Digest {
	return artifact.Digest(sha256.Sum256([]byte(packetAssessmentRule + "\n" + rawAssessmentRule + "\n" + httpAssessmentRule + "\n" + syscallAssessmentRule + "\n" + goProfileAssessmentRule + "\n" + samplerProfileAssessmentRule)))
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
		// ADR-278: on the encrypted-disk medium only one segment and the
		// headers stay in collector memory; the rest is node disk.
		ringMemory, ringRef := a.RingMaxBytes, "action:"+a.ID+":ring.maxBytes"
		if a.RingMedium == "encryptedDisk" {
			ringMemory, ringRef = a.SegmentBytes+int64(a.MaxSegments)*32, "action:"+a.ID+":ring.segmentBytes"
		}
		if a.ExecutionMode == "ongoing" {
			ringPhase, ringScope = "whileArmed", "perObservationPod"
			out.ObservationPods = 1
			ringArmed += ringMemory
		} else {
			ringIncident += ringMemory
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
			if a.PacketProfile == "rawPackets" {
				// ADR-279, REQ-ASM-003: payload prefixes are retained up to
				// the approved caps; a cap limits bytes and does not redact.
				assessed.Impact.Explanation = "Kernel packet hooks add per-packet node work and keep payload prefixes up to the approved per-transport caps; overhead depends on traffic and is not measured. Caps limit bytes and do not redact."
				assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"networkAddresses", "personalIdentifiers", "userContent", "credentials"}, TransientOnly: []string{}}
				out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "metadataOnly", Benefit: "Network headers keep no payload and need no raw approval.", CoverageLoss: "Payload bytes are not recorded."})
			}
			if a.PacketProfile == "httpHeaders" {
				// ADR-282, REQ-ASM-003: the parser inspects payload
				// transiently; the stored allowlisted fields can still
				// identify users.
				assessed.Impact.Explanation = "Packet hooks and a bounded TCP reassembly parse plain HTTP/1 headers on the node; overhead is not measured. Only method, status, Content-Type and Content-Length are kept; bodies, URLs, cookies and credentials are discarded. TLS and HTTP/2 are unsupported."
				assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"personalIdentifiers"}, TransientOnly: []string{"userContent", "credentials", "networkAddresses"}}
				out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "metadataOnly", Benefit: "Network headers read no payload and need no sensitive approval.", CoverageLoss: "HTTP methods, statuses and content types are not recorded."})
			}
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
		case "profile":
			profileAssessment(&assessed, a)
			if duration, ok := durationValue(a.Duration, false); a.ProfileType == "cpu" && ok && duration > 10*time.Second {
				out.Alternatives = append(out.Alternatives, value.AssessmentAlternative{ActionIDs: []string{a.ID}, Change: "shortenWindow", Benefit: "The default ten-second CPU profile limits how long the application or node samples.", CoverageLoss: "Activity after ten seconds is not sampled."})
			}
			out.Combined.Explanation = "Profiling overhead depends on the runtime, load and other profilers and is not measured; no profile is acquired in this release. Limits are not predictions."
			out.Interaction = "An application-owned profiler or another Asservat profile of the same runtime domain makes the request fail with ProfilerBusy; Asservat never stops it."
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
			quantity("collectorMemoryBytes", ringPhase, ringScope, ringRef, ringCoverage, ringMemory),
			quantity("collectorMemoryBytes", "perIncident", "perIncidentPod", "action:"+a.ID+":maxFrozenBytes", frozenCoverage, a.MaxFrozenBytes),
		}
		if a.Kind == "profile" {
			// A profile has no ring or frozen snapshot buffers.
			assessed.Quantities = assessed.Quantities[:1]
		}
		out.Actions = append(out.Actions, assessed)
	}
	for _, e := range []string{"applicationPause", "applicationCPU", "applicationAllocation", "forcedGC", "nodeCPU", "collectorMemory", "storageIO", "uploadContention"} {
		if effects[e] {
			out.Combined.Effects = append(out.Combined.Effects, e)
		}
	}
	if ringArmed > 0 {
		out.CombinedQuantities = append(out.CombinedQuantities, quantity("collectorMemoryBytes", "whileArmed", "wholePlan", "sum-of-declared-ring-limits", ringCoverage, ringArmed))
	}
	if plan.Actions[0].Kind != "profile" {
		// A manual plan records one evidence type; profiles have no buffers.
		out.CombinedQuantities = append(out.CombinedQuantities, quantity("collectorMemoryBytes", "perIncident", "wholePlan", "sum-of-declared-frozen-and-staging-limits", frozenCoverage, frozen+ringIncident))
	}
	out.CombinedQuantities = append(out.CombinedQuantities, quantity("outputBytes", "perIncident", "wholePlan", "sum-of-declared-output-limits", outputCoverage, output))
	if len(out.Alternatives) > 8 {
		out.Alternatives = out.Alternatives[:8]
	}
	return out, nil
}

// profileAssessment states the known effects and data categories of one
// profile action (REQ-PRF-002, specs/capture-assessment.md). A Go heap pprof
// profile holds allocation samples, not a complete object heap.
func profileAssessment(assessed *value.RecorderActionAssessment, a value.RecorderAction) {
	if a.ProfileSource == "ebpfSampler" {
		assessed.Impact = value.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"nodeCPU", "collectorMemory"},
			Explanation: "The eBPF sampler uses node CPU and collector memory during the session. Pod attribution and sampling overhead require native qualification; neither is established by this preview."}
		assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"paths"}, TransientOnly: []string{"personalIdentifiers"}}
		return
	}
	effects := []string{"applicationCPU", "applicationAllocation"}
	explanation := "The application's pprof handler samples inside the process; overhead depends on load and enabled profilers and is not measured. Sample labels, function names and paths are the application's and are not filtered."
	retained := []string{"paths", "profileLabels", "personalIdentifiers"}
	switch {
	case a.ForceGC:
		effects = append(effects, "forcedGC", "applicationPause")
		explanation = "The application runs a garbage collection before writing the heap profile, which can pause it; sampling overhead is not measured. A heap profile holds allocation samples, not a complete heap. Labels and paths are not filtered."
	case a.ProfileType == "heap":
		explanation = "The application writes its heap allocation samples without forcing a garbage collection; a heap profile is not a complete heap dump. Overhead is not measured; labels and paths are not filtered."
	case a.ProfileType == "runtimeTrace":
		explanation = "The Go execution tracer records scheduler, goroutine and log events inside the process at higher overhead and volume than sampling; it is not measured. Task, region and log text written by the application is kept unfiltered."
		retained = append(retained, "unknownApplicationData")
	case a.ProfileType == "block" || a.ProfileType == "mutex":
		explanation = "The application reports contention only if it already enabled block or mutex sampling; an empty profile can mean sampling is off. Overhead is not measured; labels and paths are not filtered."
	}
	assessed.Impact = value.AssessmentImpact{Level: "moderate", HasUnknowns: true, Effects: effects, Explanation: explanation}
	assessed.Exposure = value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: retained, TransientOnly: []string{}}
}
