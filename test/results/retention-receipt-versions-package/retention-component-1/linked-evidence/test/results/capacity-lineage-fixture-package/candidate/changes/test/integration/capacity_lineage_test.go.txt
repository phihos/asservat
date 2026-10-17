package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

const capacityNativeRetentionSeconds = int64(20)

// The renewal fixture deliberately has one original 60-second configuration.
// Select this synthetic policy before its actual acceptance, never by editing
// an existing retention checkpoint, capture, or processing row.
func capacityNativeRetentionPolicy() privacy.ScopedPolicy {
	p := retentionEffectDefaultPolicy()
	p.Policy.DefaultSeconds = capacityNativeRetentionSeconds
	p.Policy.DeletionBudgetSeconds = 1
	return p
}

func TestCapacityNativeProcessingLineageDates(t *testing.T) {
	start := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
	until := start.Add(60 * time.Second)
	target := authorization.Target{ClusterID: custodyID(), NamespaceUID: custodyID(), WorkloadUID: custodyID(), PodUID: custodyID()}
	resolve := func(t *testing.T, p privacy.ScopedPolicy, requested int64, at time.Time) privacy.Resolution {
		t.Helper()
		set := privacy.PolicySet{Target: target, Revision: p.Policy.Revision, Policies: []privacy.Policy{p.Policy}, Complete: true, ObservedAt: at, FreshUntil: at.Add(5 * time.Second)}
		r, err := privacy.Resolve(set, privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: at, RequestedSeconds: requested}, at)
		if err != nil {
			t.Fatal("fixture retention shape", err)
		}
		return r
	}
	t.Run("original-recipe-exceeds-prepaid-horizon", func(t *testing.T) {
		p := retentionEffectDefaultPolicy()
		if p.Policy.DefaultSeconds != 3600 || p.Policy.MaximumSeconds != 86400 || p.Policy.DeletionBudgetSeconds != 300 || p.CaseDefaultSeconds != 3600 || p.AuditDefaultSeconds != 3600 {
			t.Fatal("shared fixture defaults changed")
		}
		r := resolve(t, p, 3600, start.Add(12*time.Second))
		if !r.DeleteBy.After(until) || r.DeleteBy.Sub(r.AnchorAt) != 3900*time.Second {
			t.Fatal("original native failure was not reproduced by the real resolver")
		}
	})
	t.Run("explicit-policy-covers-original-session", func(t *testing.T) {
		at := start.Add(12 * time.Second)
		r := resolve(t, capacityNativeRetentionPolicy(), capacityNativeRetentionSeconds, at)
		if r.DeleteBy.After(until) || r.DeleteBy.Sub(r.AnchorAt) != 21*time.Second || !r.ExpiresAt.Equal(at.Add(20*time.Second)) {
			t.Fatal("explicit fixture policy exceeds original processing backing")
		}
		scope := artifact.DownloadScope{RootID: custodyID(), ArtifactID: custodyID(), CaptureID: custodyID(), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, PodUID: target.PodUID, Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-developer", ClientID: "console", Kind: identity.Human}}
		s := capacityNativeSession(scope, custodyID(), custodyID(), at, identity.Earlier(until, r.ExpiresAt))
		if !s.Valid() || !s.Deadline.Equal(r.ExpiresAt) || s.Deadline.After(until) {
			t.Fatal("fixture session escaped original evidence/configuration cutoffs")
		}
	})
	t.Run("same-policy-does-not-promise-future-renewal", func(t *testing.T) {
		at := until.Add(-21 * time.Second)
		exact := resolve(t, capacityNativeRetentionPolicy(), capacityNativeRetentionSeconds, at)
		late := resolve(t, capacityNativeRetentionPolicy(), capacityNativeRetentionSeconds, at.Add(time.Microsecond))
		if !exact.DeleteBy.Equal(until) || !late.DeleteBy.After(until) {
			t.Fatal("original prepaid horizon boundary changed")
		}
	})
}

// This bounded fixture read observes the complete original publication lineage
// from actual SQL. It supplies diagnostics only; the publication trigger still
// independently verifies the same facts under its own locks/current deadline.
func (f *capacitySQLFixture) checkManagedProcessingLineage(t *testing.T, expected artifact.ContextExpectation) {
	t.Helper()
	if expected.Validate() != nil {
		t.Fatal("managed processing expectation invalid")
	}
	ctx, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	var initialized, current, room, action, data, capture, artifactID, covered bool
	err := f.admin.QueryRow(ctx, `SELECT p.initialized_at IS NOT NULL,clock_timestamp()<p.valid_until,p.captures<p.max_captures,
 e->>'ActionID'='pod-status',e->>'DataClass'='metadata',(e->>'CaptureUID')::uuid=c.id,
 (e#>>'{Registration,Location,ArtifactID}')::uuid=$3::uuid,(e#>>'{Registration,DeleteBy}')::timestamptz<=p.valid_until
 FROM context_capture c JOIN processing_root p ON p.root_id=c.root_id
 CROSS JOIN LATERAL (SELECT convert_from(c.expectation_json,'UTF8')::jsonb AS e) j
 WHERE c.root_id=$1 AND c.id=$2`, f.input.PermissionRootID, expected.CaptureUID, expected.Registration.Location.ArtifactID).Scan(&initialized, &current, &room, &action, &data, &capture, &artifactID, &covered)
	if err != nil {
		t.Fatal("managed processing lineage diagnostic unavailable")
	}
	t.Logf("managed_processing_lineage initialized=%t current=%t room=%t action=%t data=%t capture=%t artifact=%t horizon=%t", initialized, current, room, action, data, capture, artifactID, covered)
	if !initialized || !current || !room || !action || !data || !capture || !artifactID || !covered {
		t.Fatal("managed processing original lineage is not publishable")
	}
}
