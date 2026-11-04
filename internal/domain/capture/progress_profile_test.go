package capture

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
)

func TestProfileUnavailableProgressIsClosedFailure(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	now := time.Now().UTC()
	p := ContextProgressObservation{CaptureID: id, CandidateCaseID: id, CandidateArtifactID: id, Target: authorization.Target{ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, Revision: 1, Phase: "Failed", ActionPhase: "Failed", ReasonCode: "ProfileUnavailable", CreatedAt: now.Add(-time.Second), Deadline: now.Add(time.Minute), ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	if !p.Valid(now) {
		t.Fatal("explicit profile refusal lost from closed progress contract")
	}
	for _, phase := range []string{"Running", "Succeeded", "Finalizing", "Indeterminate"} {
		p.Phase, p.ActionPhase = phase, phase
		if p.Valid(now) {
			t.Fatal("profile refusal escaped terminal failure", phase)
		}
	}
}
