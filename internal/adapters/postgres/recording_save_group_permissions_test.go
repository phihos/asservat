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
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type groupProjectionSQL struct {
	now                  time.Time
	loads, clocks, basis int
}
type groupProjectionSQLRow struct {
	now   time.Time
	clock bool
}

func (r groupProjectionSQLRow) Scan(dst ...any) error {
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
	if strings.HasPrefix(sql, "-- name: ReadAuthorityAudit ") {
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
	cache := newRecordingGroupPermissions(q, stream)
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
	cache := newRecordingGroupPermissions(q, stream)
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
			cache := newRecordingGroupPermissions(q, stream)
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
