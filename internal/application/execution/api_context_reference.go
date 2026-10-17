package execution

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// APIContextBudgetDigest has a distinct canonical definition. It binds the
// entire original registration (including storage, bytes and all cutoffs), not
// a new transport-selected allowance. Existing artifact/audit digests are intact.
func APIContextBudgetDigest(a capturevalue.Accepted) (artifact.Digest, error) {
	if a.Expectation.Validate() != nil || a.CaptureID != a.Expectation.CaptureUID || a.Deadline.IsZero() {
		return artifact.Digest{}, value.ErrInvalid
	}
	body, e := json.Marshal(struct {
		Format       string                `json:"format"`
		Registration artifact.Registration `json:"registration"`
		Deadline     time.Time             `json:"deadline"`
	}{"api-context-budget/v1", a.Expectation.Registration, a.Deadline})
	defer clear(body)
	if e != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	canonical := jsontext.Value(body)
	if canonical.Canonicalize() != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	return artifact.Digest(sha256.Sum256(canonical)), nil
}

// NewAPIContextWork binds a current accepted read to the independently selected
// exact channel. It does not sign, acquire or transform a passive receipt into
// authorization. All authority remains with its callers' current ports.
func NewAPIContextWork(w APIContextWork, c fleetvalue.APIContextChannel, cap planning.ContextCapability, started, until, now time.Time) (fleetvalue.APIContextWork, error) {
	a, e := w.Accepted, w.Accepted.Expectation
	budget, err := APIContextBudgetDigest(a)
	if err != nil || !c.Valid() || !cap.Valid(now) || cap.ExecutionClass != artifact.ContextAPIExecution || e.ExecutionClass != artifact.ContextAPIExecution || a.State != capturevalue.IntentAudited || !w.Actor.Valid() || w.Actor.Kind != identity.Human || !w.Target.Valid() || a.ScopeDigest != e.PlanDigest || w.Target.ClusterID != e.Registration.Location.ClusterID || w.Target.Namespace.UID != e.NamespaceUID || w.Target.Workload.UID != e.WorkloadUID || w.Target.PodUID != e.PodUID || !now.Before(a.Deadline) || !now.Before(e.Registration.WriteUntil) || c.Connector.Binding.ClusterID != w.Target.ClusterID || c.Executor.ImageDigest != e.CollectorImageDigest || cap.CollectorImageDigest != e.CollectorImageDigest {
		return fleetvalue.APIContextWork{}, value.ErrDenied
	}
	for _, d := range []time.Time{started.Add(5 * time.Second), a.Deadline, e.Registration.WriteUntil, cap.FreshUntil} {
		until = identity.Earlier(until, d)
	}
	out := fleetvalue.APIContextWork{Channel: c, CaptureID: a.CaptureID, AttemptID: e.Registration.Location.AttemptID, Actor: w.Actor, Target: authorization.Target{ClusterID: w.Target.ClusterID, NamespaceUID: w.Target.Namespace.UID, WorkloadUID: w.Target.Workload.UID, PodUID: w.Target.PodUID}, ScopeDigest: a.ScopeDigest, ExpectationDigest: evidence.ContextExpectationDigest(e), IntentDigest: w.IntentDigest, BudgetDigest: budget, Capability: cap.Revision, ProjectionDigest: cap.ProjectionDigest, IssuedAt: started.UTC().Truncate(time.Microsecond), NotAfter: until.UTC().Truncate(time.Microsecond)}
	if !out.Valid(now) {
		return fleetvalue.APIContextWork{}, value.ErrDenied
	}
	return out, nil
}
