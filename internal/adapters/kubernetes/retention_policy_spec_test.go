package kubernetes

import (
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
)

const proposedRetentionSpec = `{"scope":{},"purposeRef":"diagnostics","defaults":{"evidenceSeconds":3600,"caseMetadataSeconds":3600,"auditMetadataSeconds":3600},` +
	`"maxima":{"evidenceSeconds":7200,"caseMetadataSeconds":7200,"auditMetadataSeconds":7200},"rules":[{"name":"cores","evidenceTypes":["coreDump"],"maxAgeSeconds":3600}],"deletionBudgetSeconds":300,"legalExceptions":"disabled"}`

// ADR-240: a proposed spec passes the same schema and checks as an observed
// EvidenceRetentionPolicy; an empty scope is the baseline only for the hub.
func TestRetentionPolicySpecDecoder(t *testing.T) {
	d, err := NewRetentionPolicySpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.DecodeRetentionPolicySpec([]byte(proposedRetentionSpec), true)
	if err != nil || !p.Policy.Baseline || p.Policy.MaximumSeconds != 7200 || p.Policy.DeletionBudgetSeconds != 300 || len(p.Policy.Rules) != 1 || p.Policy.Revision.Digest == (artifact.Digest{}) || p.Policy.Revision.UID != "" || p.LegalExceptions != "disabled" {
		t.Fatalf("%v %+v", err, p)
	}
	if p, err = d.DecodeRetentionPolicySpec([]byte(proposedRetentionSpec), false); err != nil || p.Policy.Baseline {
		t.Fatalf("local empty scope became a baseline: %v %+v", err, p)
	}
	for _, bad := range []string{
		`{"purposeRef":"diagnostics"}`,
		`[]`,
		`{"scope":{"namespaceSelector":{"matchLabels":{}}},"purposeRef":"x","defaults":{"evidenceSeconds":1,"caseMetadataSeconds":1,"auditMetadataSeconds":1},"maxima":{"evidenceSeconds":1,"caseMetadataSeconds":1,"auditMetadataSeconds":1},"rules":[],"deletionBudgetSeconds":1,"legalExceptions":"disabled"}`,
	} {
		if _, err := d.DecodeRetentionPolicySpec([]byte(bad), true); !errors.Is(err, value.ErrInvalid) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}
