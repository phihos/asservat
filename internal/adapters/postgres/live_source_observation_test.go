package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"github.com/jackc/pgx/v5/pgtype"
)

func liveObservationRow(t *testing.T) (custodydb.ReadLiveSourceObservationRow, collector.SourceBinding, time.Time) {
	t.Helper()
	r := policyGrantTestRow(t)
	now := r.RequestedAt.Time.Add(time.Second)
	var p authorization.PolicyGrantScope
	if err := json.Unmarshal(r.PolicyScope, &p); err != nil {
		t.Fatal(err)
	}
	p.Limits.MaxObservedBytes = 1 << 20
	p.Authority.Limits.MaxObservedBytes = 1 << 20
	p.Observation = &authorization.ObservationLimits{MaxSessionSeconds: 60, MaxObservedBytes: 1 << 20, MaxBytesPerSecond: 1 << 20, MaxConcurrentSessions: 2}
	r.PolicyScope, _ = json.Marshal(p)
	r.PolicyMaxObservedBytes = pgtype.Int8{Int64: 1 << 20, Valid: true}
	r.Decision = grantText("approved")
	r.ApproverIssuer = grantText(r.RequesterIssuer)
	r.ApproverSubject = grantText("independent-reviewer")
	r.ApproverClient = grantText("console")
	r.DecisionReason = grantText("bounded observation")
	r.DecisionAcr = grantText("mfa")
	r.DecisionAuthTime = ts(now.Add(-time.Second))
	r.DecidedAt = ts(now)
	r.ExpiresAt = r.PolicyNotAfter
	r.Revision = 2
	if g, err := grantFromRow(r); err != nil || !g.Valid() {
		t.Fatal("typed approved observation grant fixture", err)
	}
	uuid := uid(r.ID)
	binding := collector.SourceBinding{RootID: uid(r.RootID), ObservationGrantID: uuid, PolicyUID: p.Authority.PolicyUID, AcceptanceID: uid(r.PolicyAcceptanceID), SourceID: uuid, Fence: uuid, ActionID: "packet", PodUID: uuid, NodeUID: uuid, BootID: uuid, CollectorPodUID: uuid, CollectorEpoch: uuid, Scope: [32]byte(p.Authority.ScopeDigest), ExpectationDigest: [32]byte{1}, ResourceDigest: [32]byte{2}}
	raw, _ := json.Marshal(binding)
	return custodydb.ReadLiveSourceObservationRow{AccessGrant: r, BindingJson: raw, StartedAt: ts(now), HardUntil: ts(now.Add(time.Minute)), BytesPerSecond: 1 << 20, SourceClusterID: r.ClusterID, SourceNamespaceUid: r.NamespaceUid.String, SourceWorkloadUid: r.WorkloadUid.String, PolicyObservedAt: ts(now), PolicyFreshUntil: ts(now.Add(5 * time.Second)), AuthorityDigest: bytes.Clone(binding.Scope[:])}, binding, now
}
func TestLiveSourceObservationUsesOriginalPrepaidGrantAndCutoffs(t *testing.T) {
	row, binding, now := liveObservationRow(t)
	check := func(r custodydb.ReadLiveSourceObservationRow) (time.Time, error) {
		return liveSourceObservationUntil(r, binding.RootID, binding.SourceID, binding.ObservationGrantID, now)
	}
	until, err := check(row)
	if err != nil || !until.Equal(row.PolicyFreshUntil.Time) {
		t.Fatal("original prepaid source current", err)
	}
	exhausted := row
	exhausted.AccessGrant.PolicyObservedBytesSpent = 1 << 20
	if _, err = check(exhausted); err != nil {
		t.Fatal("exhausted reservation invalidated already prepaid source", err)
	}
	for name, change := range map[string]func(*custodydb.ReadLiveSourceObservationRow){
		"revoked": func(r *custodydb.ReadLiveSourceObservationRow) {
			r.AccessGrant.RevokedAt = ts(now)
			r.AccessGrant.RevokerIssuer = grantText(r.AccessGrant.RequesterIssuer)
			r.AccessGrant.RevokerSubject = grantText("reviewer")
			r.AccessGrant.RevokerClient = grantText("console")
			r.AccessGrant.Revision = 3
		},
		"expired-policy-read": func(r *custodydb.ReadLiveSourceObservationRow) { r.PolicyFreshUntil = ts(now) },
		"longer-original-session": func(r *custodydb.ReadLiveSourceObservationRow) {
			r.HardUntil = ts(r.StartedAt.Time.Add(time.Minute + time.Microsecond))
		},
		"wider-input-rate":     func(r *custodydb.ReadLiveSourceObservationRow) { r.BytesPerSecond++ },
		"wrong-authority":      func(r *custodydb.ReadLiveSourceObservationRow) { r.AuthorityDigest = bytes.Repeat([]byte{9}, 32) },
		"wrong-workload":       func(r *custodydb.ReadLiveSourceObservationRow) { r.SourceWorkloadUid = "other" },
		"different-attachment": func(r *custodydb.ReadLiveSourceObservationRow) { r.AuthoredGrantRef = binding.RootID },
		"changed-original-grant": func(r *custodydb.ReadLiveSourceObservationRow) {
			b := binding
			b.ObservationGrantID = b.RootID
			r.BindingJson, _ = json.Marshal(b)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := row
			change(&r)
			if _, err := check(r); err == nil {
				t.Fatal("changed source grant authority accepted")
			}
		})
	}
}
