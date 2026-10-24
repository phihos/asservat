package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type ownerReadDiagnosticQuery struct {
	trust    custodydb.FleetCurrentTrust
	head     custodydb.HubOwnerConfiguration
	revision custodydb.HubOwnerConfigurationRevision
	now      pgtype.Timestamptz
	calls    []string
	fail     string
	err      error
}

type ownerReadDiagnosticRow struct {
	values []any
	err    error
}

func (r ownerReadDiagnosticRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dst) != len(r.values) {
		return errors.New("unexpected scan width")
	}
	for i, v := range r.values {
		reflect.ValueOf(dst[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}
func (q *ownerReadDiagnosticQuery) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected diagnostic effect")
}
func (q *ownerReadDiagnosticQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected diagnostic query")
}
func (q *ownerReadDiagnosticQuery) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	name := strings.Fields(sql)[2]
	q.calls = append(q.calls, name)
	if name == q.fail {
		return ownerReadDiagnosticRow{err: q.err}
	}
	var values, wantArgs []any
	switch name {
	case "ShareFleetTrust":
		v := q.trust
		values = []any{v.InstallationID, v.IssuerEpoch, v.SourceUid, v.SourceGeneration, v.SourceDigest, v.Suspended, v.RecoveryBlocked, v.ObservedAt, v.FreshUntil}
		wantArgs = []any{q.head.InstallationID}
	case "ShareOwnerConfiguration":
		v := q.head
		values = []any{v.InstallationID, v.ClusterID, v.SourceUid, v.Generation, v.ObservedAt, v.FreshUntil}
		wantArgs = []any{q.head.InstallationID, q.head.ClusterID}
	case "ReadOwnerConfigurationRevision":
		v := q.revision
		values = []any{v.InstallationID, v.ClusterID, v.SourceUid, v.Generation, v.SnapshotJson, v.AuditReceiptJson}
		wantArgs = []any{q.head.InstallationID, q.head.ClusterID, q.head.SourceUid, q.head.Generation}
	case "CurrentTime":
		values = []any{q.now}
	default:
		return ownerReadDiagnosticRow{err: errors.New("extra query")}
	}
	if !reflect.DeepEqual(args, wantArgs) {
		return ownerReadDiagnosticRow{err: errors.New("changed query binding")}
	}
	return ownerReadDiagnosticRow{values: values}
}

func ownerReadDiagnosticFixture(t *testing.T) (*OwnerConfigurations, *ownerReadDiagnosticQuery, value.OwnerConfiguration) {
	t.Helper()
	uid := func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	c := value.OwnerConfiguration{
		Pool:             value.OwnerPool{InstallationID: uid(1), ClusterID: uid(2), IssuerEpoch: uid(3), Namespace: "private", NamespaceUID: uid(4), Service: "owner", ServiceUID: uid(5), Deployment: "owner", DeploymentUID: uid(6), ServiceAccount: "owner", AccountUID: uid(7), Port: 9443},
		Revision:         identity.Revision{UID: uid(8), Generation: 1, Digest: [32]byte{1}},
		ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}},
	}
	r := audit.Receipt{Key: audit.OwnerConfigurationAuditKey(c), Version: "synthetic-version", ETag: "synthetic-etag", Bytes: 1, SHA256: artifact.Digest{4}}
	if !c.Valid() || !r.ValidOwnerConfiguration(c) {
		t.Fatal("invalid synthetic read fixture")
	}
	b, _ := json.Marshal(c)
	a, _ := json.Marshal(r)
	s := &OwnerConfigurations{installation: uid(1), cluster: uid(2), namespace: uid(4), source: uid(8)}
	q := &ownerReadDiagnosticQuery{
		trust:    custodydb.FleetCurrentTrust{InstallationID: id(uid(1)), IssuerEpoch: id(uid(3)), SourceUid: uid(9), SourceGeneration: 1, SourceDigest: []byte{1}, ObservedAt: ts(at.Add(-time.Second)), FreshUntil: ts(at.Add(4 * time.Second))},
		head:     custodydb.HubOwnerConfiguration{InstallationID: id(uid(1)), ClusterID: id(uid(2)), SourceUid: id(uid(8)), Generation: 1, ObservedAt: ts(at.Add(-time.Second)), FreshUntil: ts(at.Add(3 * time.Second))},
		revision: custodydb.HubOwnerConfigurationRevision{InstallationID: id(uid(1)), ClusterID: id(uid(2)), SourceUid: id(uid(8)), Generation: 1, SnapshotJson: b, AuditReceiptJson: a}, now: ts(at),
	}
	return s, q, c
}

func TestOwnerConfigurationReadDiagnosticPredicatesAndSingleClock(t *testing.T) {
	for _, tc := range []struct {
		name, check, reason string
		queries             int
		change              func(*ownerReadDiagnosticQuery, *value.OwnerConfiguration)
	}{
		{"valid", "transaction", "unspecified", 4, func(*ownerReadDiagnosticQuery, *value.OwnerConfiguration) {}},
		{"head-source-before-generation", "head-source", "predicate", 2, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.head.SourceUid = pgtype.UUID{}
			q.head.Generation = 0
		}},
		{"head-generation", "head-generation", "predicate", 2, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) { q.head.Generation = 0 }},
		{"decode-before-audit", "snapshot-decode", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.revision.SnapshotJson = []byte("{")
			q.revision.AuditReceiptJson = nil
		}},
		{"binding-before-suspension", "snapshot-binding", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) { c.Pool.Port = 0; c.Suspended = true }},
		{"suspension-before-generation", "snapshot-suspended", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			c.Suspended = true
			c.Revision.Generation = 2
		}},
		{"generation-before-issuer", "snapshot-generation", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			c.Revision.Generation = 2
			q.trust.IssuerEpoch = id(c.Pool.ClusterID)
		}},
		{"issuer-before-audit", "snapshot-issuer", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.IssuerEpoch = id(c.Pool.ClusterID)
			q.revision.AuditReceiptJson = nil
		}},
		{"audit-decode-before-recovery", "audit-decode", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.revision.AuditReceiptJson = nil
			q.trust.RecoveryBlocked = true
		}},
		{"audit-binding-before-recovery", "audit-binding", "predicate", 3, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.revision.AuditReceiptJson = []byte("{}")
			q.trust.Suspended = true
		}},
		{"suspended-before-blocked", "recovery-suspended", "predicate", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.Suspended = true
			q.trust.RecoveryBlocked = true
			q.trust.FreshUntil = q.now
		}},
		{"blocked-before-expiry", "recovery-blocked", "predicate", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.RecoveryBlocked = true
			q.trust.FreshUntil = q.now
		}},
		{"fleet-future-before-closed", "fleet-interval", "future-start", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.ObservedAt = ts(q.now.Time.Add(time.Second))
			q.trust.FreshUntil = q.now
		}},
		{"fleet-closed-before-expired", "fleet-interval", "closed-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.FreshUntil = q.trust.ObservedAt
		}},
		{"fleet-overlong", "fleet-interval", "overlong-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.FreshUntil = ts(q.trust.ObservedAt.Time.Add(31 * time.Second))
		}},
		{"fleet-expired-at-equality", "fleet-interval", "expired-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) { q.trust.FreshUntil = q.now }},
		{"recovery-identity-before-owner-expiry", "recovery-identity", "predicate", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.trust.SourceUid = ""
			q.head.ObservedAt = ts(q.now.Time.Add(-6 * time.Second))
		}},
		{"owner-start-expired-in-recovery", "recovery-proof-interval", "expired-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.head.ObservedAt = ts(q.now.Time.Add(-5 * time.Second))
			q.head.FreshUntil = q.now
		}},
		{"owner-start-future-in-recovery", "recovery-proof-interval", "future-start", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) {
			q.head.ObservedAt = ts(q.now.Time.Add(time.Second))
		}},
		{"owner-cutoff-expired-at-equality", "owner-interval", "expired-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) { q.head.FreshUntil = q.now }},
		{"owner-cutoff-fenced", "owner-interval", "closed-interval", 4, func(q *ownerReadDiagnosticQuery, c *value.OwnerConfiguration) { q.head.FreshUntil = q.head.ObservedAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, q, c := ownerReadDiagnosticFixture(t)
			originalJSON := slices.Clone(q.revision.SnapshotJson)
			tc.change(q, &c)
			if slices.Equal(originalJSON, q.revision.SnapshotJson) {
				q.revision.SnapshotJson, _ = json.Marshal(c)
			}
			var d ownerConfigurationReadDiagnostic
			out, err := s.readOwnerConfiguration(context.Background(), custodydb.New(q), &d)
			want := []string{"ShareFleetTrust", "ShareOwnerConfiguration", "ReadOwnerConfigurationRevision", "CurrentTime"}[:tc.queries]
			if !slices.Equal(q.calls, want) || d.check.String() != tc.check || d.reason.String() != tc.reason {
				t.Fatalf("changed query/diagnostic sequence calls=%v check=%s reason=%s", q.calls, d.check, d.reason)
			}
			if tc.name == "valid" {
				if err != nil || !out.Valid(q.now.Time) || !out.ObservedAt.Equal(q.head.ObservedAt.Time) || !out.FreshUntil.Equal(q.head.FreshUntil.Time) {
					t.Fatal("positive observation changed", err)
				}
				return
			}
			if !errors.Is(err, value.ErrUnavailable) {
				t.Fatal("predicate changed error identity", err)
			}
			var step interface{ FixedStep() string }
			if !errors.As(d.failure(err), &step) || step.FixedStep() != tc.check+"/"+tc.reason {
				t.Fatal("predicate detail is unavailable to fixed-step consumers")
			}
		})
	}
}

func TestOwnerConfigurationReadDiagnosticQueryClassesAndRetryReset(t *testing.T) {
	for _, statement := range []string{"ShareFleetTrust", "ShareOwnerConfiguration", "ReadOwnerConfigurationRevision", "CurrentTime"} {
		for _, tc := range []struct {
			name, reason string
			err          error
		}{
			{"missing", "no-rows", pgx.ErrNoRows},
			{"lock", "lock-timeout", &pgconn.PgError{Code: "55P03", Message: "private-lock-detail"}},
			{"permission", "permission", &pgconn.PgError{Code: "42501", Detail: "private-role-detail"}},
			{"query-cancel", "query-cancelled", &pgconn.PgError{Code: "57014", Message: "private-query-detail"}},
			{"context", "cancelled", context.Canceled},
			{"deadline", "deadline", context.DeadlineExceeded},
			{"driver", "driver", errors.New("private-token-password")},
			{"serialize", "unspecified", &pgconn.PgError{Code: "40001", Message: "private-query"}},
			{"deadlock", "unspecified", &pgconn.PgError{Code: "40P01", Message: "private-query"}},
		} {
			t.Run(statement+"/"+tc.name, func(t *testing.T) {
				s, q, _ := ownerReadDiagnosticFixture(t)
				q.fail, q.err = statement, tc.err
				d := ownerConfigurationReadDiagnostic{ownerReadAuditBinding, ownerReadPredicate}
				_, err := s.readOwnerConfiguration(context.Background(), custodydb.New(q), &d)
				if err != tc.err || d.reason.String() != tc.reason {
					t.Fatal("raw callback result or diagnostic changed", d.check, d.reason)
				}
				checks := map[string]OwnerConfigurationReadCheck{"ShareFleetTrust": ownerReadFleet, "ShareOwnerConfiguration": ownerReadHead, "ReadOwnerConfigurationRevision": ownerReadRevision, "CurrentTime": ownerReadClock}
				want := checks[statement]
				if tc.reason == "unspecified" {
					want = ownerReadTransaction
				}
				if d.check != want {
					t.Fatal("stale/incorrect query detail", d.check)
				}
				// Model Ledger's existing sanitization. It must be the only error
				// retained; query details cannot escape even with %+v formatting.
				wrapped := d.failure(privacy.ErrUnavailable)
				if !errors.Is(wrapped, privacy.ErrUnavailable) || errors.Is(wrapped, tc.err) {
					t.Fatal("query error escaped sanitized transaction boundary")
				}
				if strings.Contains(fmt.Sprintf("%+v", wrapped), "private-") {
					t.Fatal("driver values rendered")
				}
				var step interface{ FixedStep() string }
				if !errors.As(wrapped, &step) || step.FixedStep() != want.String()+"/"+tc.reason {
					t.Fatal("query class is unavailable to fixed-step consumers")
				}
				if tc.reason == "unspecified" {
					// A retry that fails at Begin/SET never reenters the callback.
					var failure *OwnerConfigurationReadFailure
					if !errors.As(wrapped, &failure) || failure.Check() != ownerReadTransaction || failure.Reason() != ownerReadUnspecified {
						t.Fatal("previous attempt mislabeled later transaction failure")
					}
					// A subsequent successful callback clears every previous detail;
					// a following COMMIT failure must also stay generic.
					q.fail = ""
					q.calls = nil
					if _, e := s.readOwnerConfiguration(context.Background(), custodydb.New(q), &d); e != nil || d.check != ownerReadTransaction || d.reason != ownerReadUnspecified {
						t.Fatal("successful retry retained prior diagnostic", e)
					}
				}
			})
		}
	}
}

func TestOwnerConfigurationReadDiagnosticRecoveryParityAndErrorIdentity(t *testing.T) {
	_, q, _ := ownerReadDiagnosticFixture(t)
	now := q.now.Time
	for _, start := range []time.Time{{}, now.Add(-6 * time.Second), now.Add(-5 * time.Second), now.Add(-time.Second), now, now.Add(time.Second)} {
		for _, until := range []time.Time{{}, now.Add(-time.Second), now, now.Add(time.Nanosecond), now.Add(30 * time.Second), now.Add(31 * time.Second)} {
			for _, maximum := range []time.Duration{5 * time.Second, 30 * time.Second} {
				valid := identity.Fresh(start, until, now, maximum)
				if (ownerReadIntervalFailure(start, until, now, maximum) == ownerReadUnspecified) != valid {
					t.Fatal("interval classification diverged from original predicate")
				}
			}
		}
		for mask := 0; mask < 8; mask++ {
			row := q.trust
			row.Suspended = mask&1 != 0
			row.RecoveryBlocked = mask&2 != 0
			if mask&4 != 0 {
				row.SourceUid = ""
			}
			_, err := recoveryState(row, start, now)
			d := ownerReadRecoveryFailure(row, start, now)
			if (err == nil) != (d.check == ownerReadRecoveryOther) {
				t.Fatal("recovery diagnostic diverged from original helper", mask, d.check)
			}
		}
	}
	for _, cause := range []error{value.ErrUnavailable, value.ErrInvalid, value.ErrConflict, privacy.ErrUnavailable, privacy.ErrConflict} {
		d := ownerConfigurationReadDiagnostic{ownerReadAuditBinding, ownerReadPredicate}
		err := d.failure(cause)
		if !errors.Is(err, cause) || errors.Unwrap(err) != cause {
			t.Fatal("sanitized sentinel changed")
		}
		for _, format := range []string{"%s", "%v", "%+v"} {
			if fmt.Sprintf(format, err) != "owner configuration read: audit-binding: predicate" {
				t.Fatal("diagnostic rendered non-enumerated text")
			}
		}
	}
	if (ownerConfigurationReadDiagnostic{}).failure(nil) != nil {
		t.Fatal("nil result became an error")
	}
	if OwnerConfigurationReadCheck(255).String() != "unknown" || OwnerConfigurationReadReason(255).String() != "unknown" {
		t.Fatal("unknown enum rendered uncontrolled value")
	}
}
