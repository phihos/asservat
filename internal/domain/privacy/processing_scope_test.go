package privacy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func processingIntervalScope() ProcessingScope {
	n := time.Date(2026, 11, 10, 12, 0, 0, 123000, time.FixedZone("operator", 5*3600+30*60))
	return ProcessingScope{Kind: "workloadInterval", ClusterID: processingID(1), NamespaceUID: "namespace", WorkloadUID: "workload", AcquiredFrom: n, AcquiredUntil: n.Add(time.Hour)}
}

func TestProcessingScopeEqualUsesInstantsAndExactIdentities(t *testing.T) {
	scope := processingIntervalScope()
	raw, err := json.Marshal(scope)
	if err != nil || !scope.Valid() {
		t.Fatal("valid offset interval", err)
	}
	var decoded ProcessingScope
	if json.Unmarshal(raw, &decoded) != nil || !scope.Equal(decoded) {
		t.Fatal("JSON round trip changed interval identity")
	}
	utc := scope
	utc.AcquiredFrom, utc.AcquiredUntil = scope.AcquiredFrom.UTC(), scope.AcquiredUntil.UTC()
	if !scope.Equal(utc) {
		t.Fatal("same instants in UTC differ")
	}
	for _, field := range []string{"kind", "location", "cluster", "namespace", "workload", "from", "until"} {
		changed := scope
		switch field {
		case "kind":
			changed.Kind = "artifact"
		case "location":
			changed.Location.ArtifactID = processingID(2)
		case "cluster":
			changed.ClusterID = processingID(2)
		case "namespace":
			changed.NamespaceUID += "-other"
		case "workload":
			changed.WorkloadUID += "-other"
		case "from":
			changed.AcquiredFrom = changed.AcquiredFrom.Add(time.Microsecond)
		case "until":
			changed.AcquiredUntil = changed.AcquiredUntil.Add(time.Microsecond)
		}
		if scope.Equal(changed) {
			t.Fatal("different scope accepted", field)
		}
	}
	after, err := json.Marshal(scope)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("semantic comparison changed canonical scope bytes", err)
	}
}

func TestProcessingChangeEqualPreservesRequestFields(t *testing.T) {
	change := ProcessingChange{RequestID: processingID(3), RuleID: processingID(4), Action: "restrict_processing", Scope: processingIntervalScope()}
	raw, err := json.Marshal(change)
	var decoded ProcessingChange
	if err != nil || json.Unmarshal(raw, &decoded) != nil || !change.Equal(decoded) {
		t.Fatal("JSON round trip changed request identity", err)
	}
	for _, field := range []string{"request", "rule", "artifact-selector", "action", "revision", "scope"} {
		changed := change
		switch field {
		case "request":
			changed.RequestID = processingID(5)
		case "rule":
			changed.RuleID = processingID(5)
		case "artifact-selector":
			changed.RequestedArtifactID = processingID(5)
		case "action":
			changed.Action = "release_processing"
		case "revision":
			changed.ExpectedRevision++
		case "scope":
			changed.Scope.WorkloadUID += "-other"
		}
		if change.Equal(changed) {
			t.Fatal("different request accepted", field)
		}
	}
}
