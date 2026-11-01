package privacy

import (
	"testing"
	"time"

	configuration "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

func TestCaseMetadataUsesProtectedMetadataCeilingsAndSameSourceChecks(t *testing.T) {
	f, r := acceptedRetentionTest()
	for key, s := range f.sources {
		s.Snapshot.Policies[0].CaseDefaultSeconds = 1800
		s.Snapshot.Policies[0].CaseMaximumSeconds = 2400
		s.Snapshot.Revision = identity.Revision{UID: s.Snapshot.ControlNamespaceUID, Generation: 1, Digest: configuration.RetentionSnapshotDigest(s.Snapshot)}
		f.sources[key] = s
	}
	evidence, e := r.RetentionPolicies(t.Context(), f.facts.Target)
	if e != nil {
		t.Fatal(e)
	}
	metadata, e := r.CaseMetadataPolicies(t.Context(), f.facts.Target)
	if e != nil {
		t.Fatal(e)
	}
	if metadata.Revision == evidence.Revision || !metadata.Proof.Valid(f.now) || metadata.ObservedAt != evidence.ObservedAt || metadata.FreshUntil != evidence.FreshUntil {
		t.Fatal("metadata purpose reused/renewed evidence proof")
	}
	for _, p := range metadata.Policies {
		if p.DefaultSeconds != 1800 || p.MaximumSeconds != 2400 {
			t.Fatal("metadata inherited evidence defaults", p)
		}
	}
	resolver := RetentionResolver{Policies: r, RetainedPolicies: r, Now: func() time.Time { return f.now }}
	got, e := resolver.ResolveCaseMetadata(t.Context(), value.Input{Target: f.facts.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "other", AnchorAt: f.now})
	if e != nil {
		t.Fatal(e)
	}
	if got.RequestedSeconds != 1800 || got.MaximumSeconds != 2400 {
		t.Fatal("wrong metadata resolution", got)
	}
	// The new path still rejects a current source epoch change after blocking work.
	f.sourceCalls = 0
	f.mode = "source-epoch"
	if _, e = r.CaseMetadataPolicies(t.Context(), f.facts.Target); e == nil {
		t.Fatal("metadata ignored changed source")
	}
}
