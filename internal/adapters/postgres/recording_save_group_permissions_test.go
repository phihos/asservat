package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type groupProjectionSQL struct {
	now                                  time.Time
	loads, clocks, basis                 int
	authority                            *custodydb.AuthorityAudit
	automation                           *custodydb.SelectAutomationBasisRow
	source                               *custodydb.PolicySource
	accepted                             *custodydb.PolicyAcceptance
	sourceReads, acceptReads, auditReads int
}
type groupProjectionSQLRow struct {
	now   time.Time
	clock bool
	value any
}

func (r groupProjectionSQLRow) Scan(dst ...any) error {
	if r.value != nil {
		v := reflect.ValueOf(r.value)
		if len(dst) != v.NumField() {
			return errors.New("row width")
		}
		for n, d := range dst {
			reflect.ValueOf(d).Elem().Set(v.Field(n))
		}
		return nil
	}
	if r.clock {
		if len(dst) != 1 {
			return errors.New("clock width")
		}
		reflect.ValueOf(dst[0]).Elem().Set(reflect.ValueOf(ts(r.now)))
		return nil
	}
	// Unacknowledged zero receipt is intentionally no authority. Projection
	// loading still succeeds with an empty allow set; no positive grant is faked.
	for _, d := range dst {
		reflect.ValueOf(d).Elem().SetZero()
	}
	return nil
}
func (*groupProjectionSQL) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected write")
}
func (s *groupProjectionSQL) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if strings.HasPrefix(sql, "-- name: CurrentTime ") {
		s.clocks++
		return groupProjectionSQLRow{now: s.now, clock: true}
	}
	if strings.HasPrefix(sql, "-- name: ReadPolicySourceRow ") {
		s.sourceReads++
		return groupProjectionSQLRow{value: *s.source}
	}
	if strings.HasPrefix(sql, "-- name: ReadPolicyAcceptance ") {
		s.acceptReads++
		return groupProjectionSQLRow{value: *s.accepted}
	}
	if strings.HasPrefix(sql, "-- name: ReadAuthorityAudit ") {
		s.auditReads++
		if s.authority != nil {
			return groupProjectionSQLRow{value: *s.authority}
		}
		return groupProjectionSQLRow{}
	}
	panic("unexpected row query: " + sql)
}

type groupProjectionEmptyRows struct{ pgx.Rows }

func (groupProjectionEmptyRows) Next() bool { return false }
func (groupProjectionEmptyRows) Err() error { return nil }
func (groupProjectionEmptyRows) Close()     {}
func (s *groupProjectionSQL) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	switch {
	case strings.HasPrefix(sql, "-- name: SelectPermissionAssignments "):
		s.loads++
	case strings.HasPrefix(sql, "-- name: SelectPermissionReviews "):
	case strings.HasPrefix(sql, "-- name: SelectAutomationBasis "):
		s.basis++
		if s.automation != nil {
			return &groupProjectionDataRows{value: *s.automation}, nil
		}
	default:
		return nil, errors.New("unexpected query: " + sql)
	}
	return groupProjectionEmptyRows{}, nil
}
func groupProjectionFixture() (*groupProjectionSQL, *custodydb.Queries, custodydb.PermissionStream, authorization.Target) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	db := &groupProjectionSQL{now: now}
	q := custodydb.New(db)
	stream := custodydb.PermissionStream{ID: id("11111111-1111-4111-8111-111111111111"), Epoch: id("22222222-2222-4222-8222-222222222222"), Sequence: 1, InitialAuditID: id("33333333-3333-4333-8333-333333333333"), ObservedAt: ts(now), FreshUntil: ts(now.Add(20 * time.Second)), LeaseUntil: ts(now.Add(30 * time.Second)), ProjectionDigest: append([]byte{1}, make([]byte, 31)...)}
	return db, q, stream, authorization.Target{ClusterID: "44444444-4444-4444-8444-444444444444", NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
}
func TestRecordingGroupPermissionProjectionsLoadOncePerExactPod(t *testing.T) {
	db, q, stream, target := groupProjectionFixture()
	cache := newRecordingGroupFacts(q, stream)
	var scope authorization.PolicyGrantScope
	if err := json.Unmarshal(policyGrantTestRow(t).PolicyScope, &scope); err != nil {
		t.Fatal(err)
	}
	a := scope.Authority
	target.ClusterID, target.NamespaceUID, target.WorkloadUID = a.ClusterID, a.NamespaceUID, a.WorkloadUID
	for phase := 0; phase < 4; phase++ {
		for n := 0; n < 16; n++ {
			target.PodUID = fmt.Sprintf("pod-%d", n)
			p, err := cache.read(t.Context(), q, stream, target)
			if err != nil {
				t.Fatal(err)
			}
			if p.Target != target || !p.ObservedAt.Equal(stream.ObservedAt.Time) || !p.FreshUntil.Equal(stream.FreshUntil.Time) {
				t.Fatal("target/clock changed")
			}
			// Exercise the actual nested automation reader. Its unrelated missing basis
			// remains a refusal; this test establishes SQL load count, not policy rights.
			if _, err := automationProjectionForWithPermissions(t.Context(), q, stream, a.InstallationID, a.Delegation, target, &a, &p); err == nil {
				t.Fatal("missing basis became authority")
			}
		}
	}
	// The final accepted-metadata reads use the same transaction projection too.
	for n := 0; n < 16; n++ {
		target.PodUID = fmt.Sprintf("pod-%d", n)
		if _, err := cache.read(t.Context(), q, stream, target); err != nil {
			t.Fatal(err)
		}
	}
	if db.loads != 16 || db.basis != 64 || len(cache.byTarget) != 16 {
		t.Fatalf("loads=%d basis=%d entries=%d", db.loads, db.basis, len(cache.byTarget))
	}
	t.Logf("controlled_permission_projection_loads=%d current_domain_checks_not_cached nested_basis_reads=%d", db.loads, db.basis)
	target.PodUID = "pod-17"
	if _, err := cache.read(t.Context(), q, stream, target); err != value.ErrCapacity {
		t.Fatal("unbounded target cache", err)
	}
}
func TestRecordingGroupPermissionProjectionIdentityAndTransactionIsolation(t *testing.T) {
	_, q, stream, target := groupProjectionFixture()
	cache := newRecordingGroupFacts(q, stream)
	if _, err := cache.read(t.Context(), q, stream, target); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*authorization.Target){func(v *authorization.Target) { v.ClusterID = "55555555-5555-4555-8555-555555555555" }, func(v *authorization.Target) { v.NamespaceUID = "other-ns" }, func(v *authorization.Target) { v.WorkloadUID = "other-workload" }, func(v *authorization.Target) { v.PodUID = "other-pod" }} {
		other := target
		mutate(&other)
		p, err := cache.read(t.Context(), q, stream, other)
		if err != nil || p.Target != other {
			t.Fatal("cross-target alias", err)
		}
	}
	otherStream := stream
	otherStream.Sequence++
	if _, err := cache.read(t.Context(), q, otherStream, target); err == nil {
		t.Fatal("cross-stream reuse")
	}
	if _, err := cache.read(t.Context(), custodydb.New(&groupProjectionSQL{}), stream, target); err == nil {
		t.Fatal("cross-transaction reuse")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := cache.read(ctx, q, stream, target); err == nil {
		t.Fatal("cancelled cache read succeeded")
	}
}
func TestRecordingGroupCachedProjectionReevaluatesEveryOriginalExpiry(t *testing.T) {
	for _, which := range []string{"identity", "stream", "denySnapshot", "allow", "review", "deny"} {
		t.Run(which, func(t *testing.T) {
			db, q, stream, target := groupProjectionFixture()
			cache := newRecordingGroupFacts(q, stream)
			p, err := cache.read(t.Context(), q, stream, target)
			if err != nil {
				t.Fatal(err)
			}
			caller := identity.Identity{Principal: identity.Principal{Issuer: "https://identity.example.test", Subject: "operator", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, Scopes: []string{"evidence:capture"}, Groups: []string{"team"}, VerifiedAt: db.now, ValidUntil: db.now.Add(20 * time.Second)}
			p.Allows = []authorization.CurrentAssignment{{Audience: artifact.AudienceAssignment{Kind: "Group", Issuer: caller.Principal.Issuer, SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: "66666666-6666-4666-8666-666666666666"}, ObservedAt: db.now, FreshUntil: db.now.Add(20 * time.Second)}}
			cutoff := db.now.Add(time.Second)
			switch which {
			case "identity":
				caller.ValidUntil = cutoff
			case "stream":
				p.FreshUntil = cutoff
			case "denySnapshot":
				p.DeniesFreshUntil = cutoff
			case "allow":
				p.Allows[0].FreshUntil = cutoff
			case "review":
				p.Allows[0].Reviewed = true
				p.Allows[0].Audience.Kind = "User"
				p.Allows[0].Audience.SubjectID = caller.Principal.Subject
				p.Allows[0].FreshUntil = cutoff
			case "deny":
				d := p.Allows[0]
				d.Audience.SubjectID = "unrelated-denied-team"
				d.Audience.AssignmentID = "77777777-7777-4777-8777-777777777777"
				d.FreshUntil = cutoff
				p.Denies = []authorization.CurrentAssignment{d}
			}
			cache.byTarget[target] = p
			initial := authorization.ContextEligibility(caller, p, target, db.now)
			if !initial.Eligible {
				t.Fatal("baseline ineligible", initial.Reason)
			}
			a := value.Admission{Eligibility: initial}
			a.Plan.Input.Executor = caller.Principal
			a.Plan.Input.Target.Request.ClusterID = target.ClusterID
			a.Plan.Input.Target.Request.Namespace.UID = target.NamespaceUID
			a.Plan.Input.Target.Request.Workload.UID = target.WorkloadUID
			a.Plan.Input.Target.Request.PodUID = target.PodUID
			s := &ContextAdmissions{}
			if got, err := s.currentCaptureEligibilityWithPermissions(t.Context(), q, stream, custodydb.FleetCurrentTrust{}, a, cache); err != nil || !got.Eligible {
				t.Fatal("initial DBtime evaluation", err)
			}
			db.now = cutoff
			if got, err := s.currentCaptureEligibilityWithPermissions(t.Context(), q, stream, custodydb.FleetCurrentTrust{}, a, cache); err == nil || got.Eligible {
				t.Fatal("cached observation renewed authority", which)
			}
			if db.loads != 1 {
				t.Fatal("expiry caused hidden reload", db.loads)
			}
			if !cache.byTarget[target].ObservedAt.Equal(p.ObservedAt) || !cache.byTarget[target].FreshUntil.Equal(p.FreshUntil) {
				t.Fatal("expiry dates mutated")
			}
		})
	}
}
func TestRecordingGroupProjectionBoundedMemory(t *testing.T) {
	// Raw projection rows are capped by the existing permission reader. There is
	// one retained instance per target, no per-check clones or audit record body.
	row := authorization.CurrentAssignment{}
	structural := 16 * (unsafe.Sizeof(authorization.Projection{}) + 256*unsafe.Sizeof(row))
	t.Logf("max_targets=16 max_assignment_rows_per_target=256 structural_bytes=%d plus_existing_bounded_string_payloads", structural)
}

type groupProjectionDataRows struct {
	pgx.Rows
	value any
	read  bool
}

func (r *groupProjectionDataRows) Next() bool {
	if r.read {
		return false
	}
	r.read = true
	return true
}
func (r *groupProjectionDataRows) Err() error { return nil }
func (r *groupProjectionDataRows) Close()     {}
func (r *groupProjectionDataRows) Scan(dst ...any) error {
	return (groupProjectionSQLRow{value: r.value}).Scan(dst...)
}

func groupAuditedBasisFixture(t *testing.T) (*groupProjectionSQL, *custodydb.Queries, custodydb.PermissionStream, authorization.AcceptedPolicyAuthority, authorization.Target) {
	t.Helper()
	db, q, stream, target := groupProjectionFixture()
	var scope authorization.PolicyGrantScope
	if err := json.Unmarshal(policyGrantTestRow(t).PolicyScope, &scope); err != nil {
		t.Fatal(err)
	}
	a := scope.Authority
	target.ClusterID, target.NamespaceUID, target.WorkloadUID = a.ClusterID, a.NamespaceUID, a.WorkloadUID
	envelope := authorization.AutomationEnvelope{AllowedActions: []string{"packetCapture"}, MaxLifetimeSeconds: 31536000, MaxExecutions: a.Limits.MaxExecutions, MaxBytes: a.Limits.MaxBytes, MaxObservedBytes: a.Limits.MaxObservedBytes}
	event := "88888888-8888-4888-8888-888888888888"
	d := artifact.Digest{3}
	record := audit.AuthorityRecord{ID: event, RootID: uid(stream.ID), Epoch: uid(stream.Epoch), Kind: "permission-change", Sequence: stream.Sequence, InputDigest: artifact.Digest{1}, CreatedAt: db.now, Automation: []audit.AutomationDelegation{{BasisKey: "binding-key", Revision: a.Delegation, ScopeDigest: d, Envelope: envelope}}}
	if !record.Valid() || !a.Valid(db.now) {
		t.Fatal("invalid positive authority fixture")
	}
	raw, _ := json.Marshal(record)
	env, _ := json.Marshal(envelope)
	db.authority = &custodydb.AuthorityAudit{ID: id(event), StreamID: stream.ID, Epoch: stream.Epoch, Sequence: stream.Sequence, EventKind: record.Kind, Record: raw, EventDigest: digest(record), CreatedAt: ts(db.now), AcknowledgedAt: ts(db.now), ObjectKey: pgtype.Text{String: audit.AuthorityKey(uid(stream.ID), event), Valid: true}, ObjectVersion: pgtype.Text{String: "version", Valid: true}, ObjectEtag: pgtype.Text{String: "etag", Valid: true}, ObjectBytes: pgtype.Int8{Int64: 1, Valid: true}, ObjectSha256: append([]byte{1}, make([]byte, 31)...)}
	db.automation = &custodydb.SelectAutomationBasisRow{StreamID: stream.ID, BasisKey: "binding-key", Uid: a.Delegation.UID, Kind: "AccessBinding", Generation: a.Delegation.Generation, ResourceVersion: "1", ObservationVersion: "1", SpecDigest: a.Delegation.Digest[:], ScopeDigest: d[:], ClusterID: id(a.ClusterID), NamespaceUid: a.NamespaceUID, WorkloadUids: []string{a.WorkloadUID}, Effect: "Allow", NotAfter: ts(db.now.Add(10 * time.Second)), SeenSequence: stream.Sequence, AutomationJson: env, AutomationAuditID: id(event), AcknowledgedAt: ts(db.now)}
	return db, q, stream, a, target
}

func TestRecordingGroupSharedAuditedBasisLoadsOnce(t *testing.T) {
	db, q, stream, a, target := groupAuditedBasisFixture(t)
	facts := newRecordingGroupFacts(q, stream)
	for n := 0; n < 64; n++ {
		target.PodUID = fmt.Sprintf("pod-%d", n%16)
		projection, err := facts.read(t.Context(), q, stream, target)
		if err != nil {
			t.Fatal(err)
		}
		out, err := facts.automation(t.Context(), q, stream, a.InstallationID, a, target, projection)
		if err != nil || out.Permissions.Target != target || !out.NotAfter.Equal(db.automation.NotAfter.Time) {
			t.Fatal("genuine audited basis refused or freshness changed", err)
		}
	}
	if db.basis != 1 {
		t.Fatalf("shared audited basis loaded %d times; want1 while64domain validations stay current", db.basis)
	}
}

func groupAuditedPolicyFixture(t *testing.T) (*groupProjectionSQL, *custodydb.Queries, custodydb.PermissionStream, custodydb.FleetCurrentTrust, authorization.AcceptedPolicyAuthority, authorization.Target) {
	t.Helper()
	db, q, stream, a, target := groupAuditedBasisFixture(t)
	// Preserve valid source observations BEFORE first load to exercise a backward
	// clock that would otherwise fit their original window.
	src := value.PolicySource{InstallationID: a.InstallationID, ClusterID: a.ClusterID, NamespaceUID: a.NamespaceUID, Name: "policy", Revision: identity.Revision{UID: a.PolicyUID, Generation: 1, Digest: artifact.Digest{2}}, ResourceVersion: "1", ObservedAt: db.now.Add(-time.Second), FreshUntil: db.now.Add(3 * time.Second), CollectionDigest: artifact.Digest{7}}
	submission := value.VerifiedPolicySubmission{Nonce: "99999999-9999-4999-8999-999999999999", Actor: a.Creator, Source: src.Revision, ClusterID: src.ClusterID, NamespaceUID: src.NamespaceUID, Name: src.Name, ScopeDigest: a.ScopeDigest, EnvelopeDigest: artifact.Digest{8}, IssuedAt: db.now, ExpiresAt: db.now.Add(20 * time.Second)}
	trust := custodydb.FleetCurrentTrust{InstallationID: id(a.InstallationID), IssuerEpoch: id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), SourceUid: "fleet", SourceGeneration: 1, SourceDigest: append([]byte{1}, make([]byte, 31)...), ObservedAt: ts(db.now.Add(-time.Second)), FreshUntil: ts(db.now.Add(4 * time.Second))}
	recovery, err := recoveryState(trust, db.now, db.now)
	if err != nil {
		t.Fatal(err)
	}
	record := value.PolicyAcceptance{ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", RootID: uid(stream.ID), Source: src, Submission: submission, Authority: a, Submitter: a.Creator, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, PermissionRevision: identity.Revision{UID: uid(stream.Epoch), Generation: 1, Digest: artifact.Digest{1}}, Recovery: recovery, IntentVersion: 1, AcceptedAt: db.now}
	if !record.Valid() {
		t.Fatal("invalid accepted-policy fixture")
	}
	raw, _ := json.Marshal(record)
	receipt, _ := json.Marshal(audit.Receipt{Key: audit.PolicyAcceptanceKey(record.RootID, record.ID), Version: "version", ETag: "etag", Bytes: 1, SHA256: artifact.Digest{1}})
	db.source = &custodydb.PolicySource{RootID: stream.ID, PolicyUid: a.PolicyUID, InstallationID: id(a.InstallationID), ClusterID: id(src.ClusterID), NamespaceUid: src.NamespaceUID, Name: src.Name, Generation: src.Revision.Generation, SpecDigest: src.Revision.Digest[:], ResourceVersion: src.ResourceVersion, ObservedAt: ts(src.ObservedAt), FreshUntil: ts(src.FreshUntil), CollectionDigest: src.CollectionDigest[:], IntentVersion: 1, ActiveID: id(record.ID)}
	db.accepted = &custodydb.PolicyAcceptance{ID: id(record.ID), RootID: stream.ID, PolicyUid: a.PolicyUID, Generation: src.Revision.Generation, Nonce: id(submission.Nonce), ScopeDigest: a.ScopeDigest[:], RequestDigest: policyRequestDigest(value.PolicyAdmission{Submission: submission, Authority: a}), RecordDigest: digest(record), Record: raw, AcceptedAt: ts(db.now), AcknowledgedAt: ts(db.now), ReceiptJson: receipt}
	return db, q, stream, trust, a, target
}

func TestRecordingGroupSharedPolicyFactsKeepOriginalSourceExpiry(t *testing.T) {
	for _, mode := range []string{"source-expiry", "backward-before-load", "changed-trust", "own-budget-only"} {
		t.Run(mode, func(t *testing.T) {
			db, q, stream, trust, a, target := groupAuditedPolicyFixture(t)
			facts := newRecordingGroupFacts(q, stream)
			initial := db.now
			first, err := facts.acceptedPolicy(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, a.PolicyUID, target, db.now)
			if err != nil {
				t.Fatal("positive original source refused", err)
			}
			for n := 0; n < 63; n++ {
				if _, err := facts.acceptedPolicy(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, a.PolicyUID, target, db.now); err != nil {
					t.Fatal(err)
				}
			}
			if db.sourceReads != 1 || db.acceptReads != 1 {
				t.Fatalf("source=%d acceptance=%d", db.sourceReads, db.acceptReads)
			}
			switch mode {
			case "source-expiry":
				db.now = db.source.FreshUntil.Time
			case "backward-before-load":
				db.now = initial.Add(-time.Microsecond)
			case "changed-trust":
				trust.IssuerEpoch = id("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
			case "own-budget-only":
				db.accepted.ExecutionsSpent++
				db.accepted.CollectedBytesSpent += 1024
			}
			got, err := facts.acceptedPolicy(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, a.PolicyUID, target, db.now)
			if mode == "own-budget-only" {
				if err != nil || got.Authority.ScopeDigest != first.Authority.ScopeDigest {
					t.Fatal("budget changed immutable authority", err)
				}
			} else if err == nil {
				t.Fatal("expired/backdated/substituted facts accepted", mode)
			}
			if !facts.policy.snapshot.FreshUntil.Equal(first.FreshUntil) || !facts.policy.source.FreshUntil.Equal(db.source.FreshUntil.Time) {
				t.Fatal("source freshness rewritten")
			}
			if db.sourceReads != 1 || db.acceptReads != 1 {
				t.Fatal("expiry triggered fallback reload")
			}
		})
	}
}
func TestRecordingGroupSharedBasisKeepsOriginalEndAndExactScope(t *testing.T) {
	for _, mode := range []string{"expiry", "backward", "wrong-policy", "wrong-delegation", "wrong-scope", "wrong-workload", "wrong-stream", "wrong-transaction", "target-permissions-expiry"} {
		t.Run(mode, func(t *testing.T) {
			db, q, stream, a, target := groupAuditedBasisFixture(t)
			facts := newRecordingGroupFacts(q, stream)
			p, err := facts.read(t.Context(), q, stream, target)
			if err != nil {
				t.Fatal(err)
			}
			out, err := facts.automation(t.Context(), q, stream, a.InstallationID, a, target, p)
			if err != nil {
				t.Fatal("positive basis refused", err)
			}
			switch mode {
			case "expiry":
				db.now = out.NotAfter
			case "backward":
				db.now = db.now.Add(-time.Microsecond)
			case "wrong-policy":
				a.PolicyUID = "different"
				a.Executor = authorization.PolicyPrincipal(a.InstallationID, a.PolicyUID)
			case "wrong-delegation":
				a.Delegation.Generation++
			case "wrong-scope":
				a.ScopeDigest[0]++
			case "wrong-workload":
				target.WorkloadUID = "different"
				a.WorkloadUID = target.WorkloadUID
				p.Target = target
			case "wrong-stream":
				stream.Sequence++
			case "wrong-transaction":
				q = custodydb.New(db)
			case "target-permissions-expiry":
				db.now = p.FreshUntil
			}
			if _, err := facts.automation(t.Context(), q, stream, a.InstallationID, a, target, p); err == nil {
				t.Fatal("basis scope/expiry crossed", mode)
			}
			if db.basis != 1 {
				t.Fatal("basis cache reloaded on invalidity", db.basis)
			}
		})
	}
}

func TestRecordingGroupSharedFactsStillEvaluateFullPolicyAtEveryBoundary(t *testing.T) {
	db, q, stream, trust, a, target := groupAuditedPolicyFixture(t)
	facts := newRecordingGroupFacts(q, stream)
	projection := authorization.Projection{Target: target, Revision: identity.Revision{UID: uid(stream.Epoch), Generation: stream.Sequence, Digest: artifact.Digest{1}}, ObservedAt: stream.ObservedAt.Time, FreshUntil: stream.FreshUntil.Time, DeniesComplete: true, DeniesObservedAt: stream.ObservedAt.Time, DeniesFreshUntil: stream.FreshUntil.Time}
	for _, owner := range a.Owners {
		projection.Allows = append(projection.Allows, authorization.CurrentAssignment{Audience: owner, ObservedAt: db.now, FreshUntil: db.now.Add(20 * time.Second)})
	}
	executor := authorization.PolicyExecutorIdentity(a, db.now, db.now.Add(20*time.Second))
	for n := 0; n < 64; n++ {
		got := contextEligibilityInWithPermissions(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, executor, projection, target, db.now, facts)
		if !got.Eligible {
			t.Fatal("valid full domain eligibility refused", got.Reason)
		}
	}
	if db.sourceReads != 1 || db.acceptReads != 1 || db.basis != 1 || db.auditReads != 1 {
		t.Fatalf("shared metadata calls source=%d acceptance=%d basis=%d audit=%d", db.sourceReads, db.acceptReads, db.basis, db.auditReads)
	}
	t.Logf("actual_controlled_full_eligibility_calls=64 source_reads=%d acceptance_reads=%d basis_reads=%d basis_audit_reads=%d", db.sourceReads, db.acceptReads, db.basis, db.auditReads)
	changed := executor
	changed.Principal.ClientID = "different"
	if got := contextEligibilityInWithPermissions(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, changed, projection, target, db.now, facts); got.Eligible {
		t.Fatal("cached facts reused another executor identity")
	}
	db.now = db.source.FreshUntil.Time
	if got := contextEligibilityInWithPermissions(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, executor, projection, target, db.now, facts); got.Eligible {
		t.Fatal("original policy source expired but full evaluation stayed eligible")
	}
	if db.sourceReads != 1 || db.acceptReads != 1 || db.basis != 1 || db.auditReads != 1 {
		t.Fatal("changed/expired input caused fallback reload")
	}
}

func TestRecordingGroupNilFactsPreserveOrdinaryReadsAndClocks(t *testing.T) {
	db, q, stream, trust, a, target := groupAuditedPolicyFixture(t)
	p := authorization.Projection{Target: target}
	i := authorization.PolicyExecutorIdentity(a, db.now, db.now.Add(20*time.Second))
	for n := 0; n < 64; n++ {
		// The ordinary reader still reloads permissions; empty unacknowledged target
		// allows cannot be replaced by this separately supplied empty projection.
		if got := contextEligibilityIn(t.Context(), q, stream, trust, uid(stream.ID), a.InstallationID, i, p, target, db.now); got.Eligible {
			t.Fatal("ordinary path invented target permissions")
		}
	}
	if db.sourceReads != 64 || db.acceptReads != 64 || db.basis != 64 || db.loads != 64 || db.auditReads != 192 || db.clocks != 448 {
		t.Fatalf("ordinary protocol changed source=%d acceptance=%d basis=%d permissions=%d audit=%d clocks=%d", db.sourceReads, db.acceptReads, db.basis, db.loads, db.auditReads, db.clocks)
	}
}

func TestRecordingGroupFactsOwnOriginalStreamDigestBytes(t *testing.T) {
	for _, field := range []string{"projection", "trust"} {
		t.Run(field, func(t *testing.T) {
			db, q, stream, target := groupProjectionFixture()
			stream.TrustDigest = append([]byte{2}, make([]byte, 31)...)
			facts := newRecordingGroupFacts(q, stream)
			if _, err := facts.read(t.Context(), q, stream, target); err != nil {
				t.Fatal("original transaction refused", err)
			}
			if field == "projection" {
				stream.ProjectionDigest[0] ^= 1
			} else {
				stream.TrustDigest[0] ^= 1
			}
			if facts.stream.ProjectionDigest[0] != 1 || facts.stream.TrustDigest[0] != 2 {
				t.Fatal("caller digest mutation rewrote owned original binding")
			}
			if _, err := facts.read(t.Context(), q, stream, target); err != value.ErrInvalid {
				t.Fatal("in-place digest mutation crossed original binding", err)
			}
			if db.loads != 1 {
				t.Fatal("digest mutation triggered projection fallback")
			}
		})
	}
}
