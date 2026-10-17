package presentation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) {
	return nil, fmt.Errorf("network schema loading disabled")
}

func canonicalSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.UseLoader(offlineLoader{})
	c.AssertFormat()
	for _, file := range []string{"common.schema.json", "privacy-common.schema.json", "capture-assessment.schema.json", "action-lifecycle.schema.json"} {
		b, err := os.ReadFile("../../../specs/contracts/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if err = c.AddResource(doc["$id"].(string), doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile("https://asservat.io/spec/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func assessmentFixture() value.ContextAssessment {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	return value.ContextAssessment{ID: "00000000-0000-4000-8000-000000000088", PlanDigest: artifact.Digest{1}, RulesDigest: artifact.Digest{2}, CapabilityDigest: artifact.Digest{3}, GeneratedAt: now, ValidUntil: now.Add(5 * time.Second),
		Impact:    value.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"collectorMemory", "storageIO", "uploadContention"}, Explanation: "Overhead is unmeasured."},
		Exposure:  value.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"personalIdentifiers"}, TransientOnly: []string{"userContent", "credentials"}, UnknownContent: true},
		Retention: value.AssessmentRetention{AccessAgeSeconds: 3600, DeleteAgeSeconds: 3900, MaximumAgeSeconds: 86400, DeletionBudgetSeconds: 300, PolicyDigests: []artifact.Digest{{4}}}, OutputLimit: 4096}
}

func TestContextReviewMatchesCanonicalContracts(t *testing.T) {
	a := ContextAssessment(assessmentFixture())
	for _, pair := range []struct {
		name  string
		value any
	}{{"capture-assessment.schema.json#/$defs/assessment", a}, {"action-lifecycle.schema.json#/$defs/plan", ContextLifecycle()}} {
		b, err := json.Marshal(pair.value)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if err = canonicalSchema(t, pair.name).Validate(v); err != nil {
			t.Fatal(err)
		}
	}
	if a.Scope.ObservationPods != 0 || a.Scope.IncidentPods != 1 || a.CombinedQuantities[0].Basis != "configuredLimit" || a.CombinedQuantities[0].Lower != 0 {
		t.Fatal("one-shot limit presented as continuous collection or expected bytes")
	}
	if a.Basis.Metrics.State != "unavailable" || a.Actions[0].Retention.PreservationException != "possible" {
		t.Fatal("unknown measurements/preservation replaced by unsupported promise")
	}
	if a.Actions[0].Retention.DeleteAgeSeconds == a.Actions[0].Retention.MaximumAgeSeconds {
		t.Fatal("shorter requested deletion age lost")
	}
	if a.Actions[0].Retention.AnchorRule != "submissionPreparation" {
		t.Fatal("context retention promised a later acquisition-time anchor")
	}
}

func TestAssessmentAnchorContractPreservesOtherMechanisms(t *testing.T) {
	schema := canonicalSchema(t, "capture-assessment.schema.json#/$defs/assessment")
	for _, anchor := range []string{"submissionPreparation", "firstAcquisitionOrEarlierSource", "uploadCompletion"} {
		a := ContextAssessment(assessmentFixture())
		a.Actions[0].Retention.AnchorRule = anchor
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if valid := schema.Validate(v) == nil; valid != (anchor != "uploadCompletion") {
			t.Fatalf("anchor %q validity %v", anchor, valid)
		}
	}
}

func TestContextProjectionDetachedAndBounded(t *testing.T) {
	input := assessmentFixture()
	for n := 1; n < 64; n++ {
		input.Retention.PolicyDigests = append(input.Retention.PolicyDigests, artifact.Digest{byte(n), 1})
	}
	a := ContextAssessment(input)
	input.Impact.Effects[0] = "applicationPause"
	input.Exposure.TransientOnly[0] = "paths"
	a.Actions[0].Impact.Effects[0] = "applicationCPU"
	if a.CombinedImpact.Effects[0] != "collectorMemory" || a.Actions[0].Data.TransientOnly[0] != "userContent" {
		t.Fatal("projection aliases mutable input/action state")
	}
	b, err := json.Marshal(a)
	if err != nil || len(b) > 24<<10 {
		t.Fatalf("bounded review too large: %d %v", len(b), err)
	}
	if bytes.Contains(b, []byte("expiresAt")) || bytes.Contains(b, []byte("deleteBy")) {
		t.Fatal("future evidence received absolute preview-time expiry")
	}
}
