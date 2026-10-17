package planning

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestContextRetentionAnchorChangeInvalidatesOldRulesForBothClasses(t *testing.T) {
	// These are the qualified v1 rule digests, before the retention anchor was
	// part of the explanation. A newly reviewed draft must not reuse either.
	legacy := map[artifact.ContextExecutionClass]string{
		artifact.ContextNodeExecution: "50bade393d4dca58374e58e5478aded51b98a5be9fec17f5e23e88321ea91bb4",
		artifact.ContextAPIExecution:  "bdeec016b739b4d465ead76af39f8153cb55ac80c57b919d9a4be4c9fd551bbe",
	}
	for class, previous := range legacy {
		current := ContextAssessmentRulesDigestForClass(class)
		if current == (artifact.Digest{}) || hex.EncodeToString(current[:]) == previous {
			t.Fatalf("class %q retained the old anchor rule digest", class)
		}
	}
	if ContextAssessmentRulesDigestForClass(artifact.ContextNodeExecution) == ContextAssessmentRulesDigestForClass(artifact.ContextAPIExecution) {
		t.Fatal("anchor correction erased execution-class distinction")
	}
}

func TestAPIContextAssessmentLocatesWorkOutsideObservedNode(t *testing.T) {
	in, now := contextInput(t)
	in.Target.ExecutionClass = artifact.ContextAPIExecution
	in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = "", "", ""
	in.Capability.ExecutionClass = artifact.ContextAPIExecution
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := AssessContext(plan, "00000000-0000-4000-8000-000000000088", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.RulesDigest == ContextAssessmentRulesDigest() || !strings.Contains(a.Impact.Explanation, "regional collector") || !a.Impact.HasUnknowns {
		t.Fatal("execution class lost from explanation/review digest")
	}
}

func TestContextAssessmentExplainsActualRetentionAndUnknownCost(t *testing.T) {
	in, now := contextInput(t)
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := AssessContext(plan, "00000000-0000-4000-8000-000000000088", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.PlanDigest != plan.ScopeDigest || !a.ValidUntil.Equal(plan.ValidUntil) || a.RulesDigest == (artifact.Digest{}) {
		t.Fatal("assessment lost scope or original freshness")
	}
	if a.Impact.Level != "unknown" || !a.Impact.HasUnknowns || a.OutputLimit != 4096 {
		t.Fatal("output cap was presented as an overhead forecast")
	}
	if a.Exposure.Classification != "potentialPersonalData" || len(a.Exposure.TransientOnly) == 0 {
		t.Fatal("projection hid transient raw pod response risk")
	}
	// Native status excludes addresses/paths, but encrypted provenance retains
	// issuer URLs. The assessment covers the whole artifact, including manifest.
	for _, category := range []string{"networkAddresses", "paths"} {
		if !slices.Contains(a.Exposure.RetainedPossible, category) || slices.Contains(a.Exposure.TransientOnly, category) {
			t.Fatal("retained identity provenance was described as transient-only")
		}
	}
	if a.Retention.AccessAgeSeconds != 3600 || a.Retention.DeleteAgeSeconds != 3900 || a.Retention.MaximumAgeSeconds != 86400 {
		t.Fatal("deletion age was replaced by the administrator maximum")
	}
	// Report ownership must not expose mutable references to the compiled plan.
	a.Retention.PolicyDigests[0][0]++
	if !VerifyContextPlan(plan, now) {
		t.Fatal("assessment mutated original plan")
	}
	for _, at := range []time.Time{now.Add(-time.Microsecond), plan.ValidUntil, plan.ValidUntil.Add(time.Second)} {
		if _, err := AssessContext(plan, a.ID, at); err == nil {
			t.Fatal("stale or future-dated facts accepted")
		}
	}
	if _, err := AssessContext(plan, "bad-id", now); err == nil {
		t.Fatal("invalid assessment identity accepted")
	}
}

func TestContextAssessmentClampedLifetimeAndDuplicatePolicyDefinitions(t *testing.T) {
	in, now := contextInput(t)
	in.Retention.RequestedSeconds = 86400
	in.Retention.ExpiresAt = now.Add(86100 * time.Second)
	in.Retention.DeleteBy = now.Add(86400 * time.Second)
	ref := in.Retention.Policies[0]
	ref.UID = "independent-same-policy"
	in.Retention.Policies = append(in.Retention.Policies, ref)
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := AssessContext(plan, "00000000-0000-4000-8000-000000000088", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Retention.AccessAgeSeconds != 86100 || a.Retention.DeleteAgeSeconds != 86400 || len(a.Retention.PolicyDigests) != 1 {
		t.Fatal("effective retention/deduplicated rule projection incorrect")
	}
}
