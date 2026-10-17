package planning

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// ContextAssessment is an explanatory projection of the qualified pod-status
// recipe. It contains neither acquisition authority nor a promise about measured
// overhead. Relative ages apply at first acquisition, not at preview creation.
type ContextAssessment struct {
	ID                                        string
	PlanDigest, RulesDigest, CapabilityDigest artifact.Digest
	GeneratedAt, ValidUntil                   time.Time
	Impact                                    AssessmentImpact
	Exposure                                  AssessmentExposure
	Retention                                 AssessmentRetention
	OutputLimit                               int64
}

type AssessmentImpact struct {
	Level, Explanation string
	HasUnknowns        bool
	Effects            []string
}

type AssessmentExposure struct {
	Classification, Basis           string
	RetainedPossible, TransientOnly []string
	UnknownContent                  bool
}

type AssessmentRetention struct {
	AccessAgeSeconds, DeleteAgeSeconds, MaximumAgeSeconds, DeletionBudgetSeconds int64
	PolicyDigests                                                                []artifact.Digest
}
