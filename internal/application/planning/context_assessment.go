package planning

import (
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
)

// The reviewed rule is intentionally limited to the exact compiled projection.
// A change to its effects, exposure or interpretation requires a new rule digest.
const contextAssessmentRule = `{"rule":"pod-status-assessment/v2","retentionAnchorRule":"submissionPreparation","recipe":"builtin-pod-status-v1","impact":"unknown","effects":["nodeCPU","collectorMemory","storageIO","uploadContention"],"retained":["personalIdentifiers","networkAddresses","paths"],"transient":["userContent","credentials","unknownApplicationData"],"metrics":"unavailable","limit":{"nativeOutputBytes":4096,"excludes":"API response, framing, encryption and total collector memory"}}`

func ContextAssessmentRulesDigest() artifact.Digest {
	return ContextAssessmentRulesDigestForClass(artifact.ContextNodeExecution)
}

// The v2 rule names the submission-preparation retention anchor, invalidating
// unsubmitted v1 drafts that described a later acquisition anchor. API-only work
// retains its separate digest and regional resource explanation. Historical
// accepted operations keep their registration and are recovered before review
// rule comparison; this rule does not rewrite stored artifact or audit bytes.
func ContextAssessmentRulesDigestForClass(class artifact.ContextExecutionClass) artifact.Digest {
	switch class {
	case artifact.ContextNodeExecution:
		return artifact.Digest(sha256.Sum256([]byte(contextAssessmentRule)))
	case artifact.ContextAPIExecution:
		return artifact.Digest(sha256.Sum256([]byte(contextAssessmentRule + "\nexecutionClass=kubernetesAPI;collectorPlacement=regional;observedNodeAccess=none")))
	default:
		return artifact.Digest{}
	}
}

// AssessContext performs no I/O or trial acquisition. Authorization belongs to
// the caller; this function must not be used to disclose a target to an ineligible
// requester. A stored preview can retain this explanation, but submission must
// compile and assess current facts again.
func AssessContext(plan value.ContextPlan, assessmentID string, now time.Time) (value.ContextAssessment, error) {
	if !authorization.UUID(assessmentID) || !VerifyContextPlan(plan, now) || now.Before(plan.CompiledAt) {
		return value.ContextAssessment{}, value.ErrInvalid
	}
	r := plan.Input.Retention
	digests := make([]artifact.Digest, 0, len(r.Policies))
	seen := make(map[artifact.Digest]bool, len(r.Policies))
	for _, policy := range r.Policies {
		if !seen[policy.Digest] {
			digests = append(digests, policy.Digest)
			seen[policy.Digest] = true
		}
	}
	explanation := "Uses the Kubernetes API server and collector; no process attach or application command. Status reads, encryption and upload consume resources. Current load and combined overhead are unmeasured."
	if plan.Input.Target.ExecutionClass == artifact.ContextAPIExecution {
		explanation = "Uses the Kubernetes API and a regional collector for CPU, memory, encryption and upload work. It does not access the observed Pod's node or attach to an application process. Shared infrastructure pressure and combined overhead are unmeasured."
	}
	return value.ContextAssessment{
		ID: assessmentID, PlanDigest: plan.ScopeDigest,
		RulesDigest: ContextAssessmentRulesDigestForClass(plan.Input.Target.ExecutionClass), CapabilityDigest: artifact.Digest(plan.Input.Capability.Revision.Digest),
		GeneratedAt: now, ValidUntil: plan.ValidUntil,
		Impact: value.AssessmentImpact{
			Level: "unknown", HasUnknowns: true,
			Effects:     []string{"nodeCPU", "collectorMemory", "storageIO", "uploadContention"},
			Explanation: explanation,
		},
		Exposure: value.AssessmentExposure{
			Classification: "potentialPersonalData", Basis: "conservativeMechanism",
			RetainedPossible: []string{"personalIdentifiers", "networkAddresses", "paths"},
			TransientOnly:    []string{"userContent", "credentials", "unknownApplicationData"},
			UnknownContent:   true,
		},
		Retention: value.AssessmentRetention{
			AccessAgeSeconds:  int64(r.ExpiresAt.Sub(r.AnchorAt) / time.Second),
			DeleteAgeSeconds:  int64(r.DeleteBy.Sub(r.AnchorAt) / time.Second),
			MaximumAgeSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds,
			PolicyDigests: digests,
		},
		OutputLimit: artifact.MaxContextBytes,
	}, nil
}
