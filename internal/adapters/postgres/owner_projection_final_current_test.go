package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type ownerProjectionReasonContext struct {
	context.Context
	failure error
	reads   int
}

func (c *ownerProjectionReasonContext) Err() error {
	c.reads++
	return c.failure
}

type ownerProjectionPrivateDiagnosticError struct{}

func (ownerProjectionPrivateDiagnosticError) Error() string {
	panic("raw diagnostic error must not be rendered")
}
func (ownerProjectionPrivateDiagnosticError) Unwrap() error {
	panic("raw diagnostic error must not be unwrapped")
}

func TestOwnerProjectionFinalCurrentReasonPreservesShortCircuit(t *testing.T) {
	until := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name            string
		current, ctx    error
		now             time.Time
		want            OwnerProjectionSQLReason
		contexts, times int
	}{
		{"success", nil, nil, until.Add(-time.Nanosecond), ownerProjectionSQLReasonUnspecified, 1, 1},
		{"exact-boundary", nil, nil, until, ownerProjectionSQLReasonDeadline, 1, 1},
		{"after-boundary", nil, nil, until.Add(time.Nanosecond), ownerProjectionSQLReasonDeadline, 1, 1},
		{"current-before-cancel-and-clock", ownerIdentityPrerequisiteError("source-current"), context.Canceled, until, ownerProjectionSQLReasonCurrentSource, 0, 0},
		{"current-unknown", ownerProjectionPrivateDiagnosticError{}, context.Canceled, until, ownerProjectionSQLReasonCurrentUnknown, 0, 0},
		{"cancel-before-clock", nil, context.Canceled, until, ownerProjectionSQLReasonContextCancelled, 1, 0},
		{"context-deadline-before-clock", nil, context.DeadlineExceeded, until, ownerProjectionSQLReasonContextDeadline, 1, 0},
		{"context-unknown-before-clock", nil, ownerProjectionPrivateDiagnosticError{}, until, ownerProjectionSQLReasonContextUnknown, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &ownerProjectionReasonContext{Context: context.Background(), failure: tc.ctx}
			times := 0
			reason := ownerProjectionFinalCurrentReason(ctx, tc.current, until, func() time.Time { times++; return tc.now })
			if reason != tc.want || ctx.reads != tc.contexts || times != tc.times {
				t.Fatal("original deciding predicate or short-circuit reads changed", reason, ctx.reads, times)
			}
		})
	}
}

func TestOwnerProjectionFinalCurrentReasonUsesActualSingleSQLResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		want OwnerProjectionSQLReason
	}{
		{"administrator", ownerProjectionSQLReasonCurrentAdministrator},
		{"schema", ownerProjectionSQLReasonCurrentSchema},
		{"activation", ownerProjectionSQLReasonCurrentActivation},
		{"recovery", ownerProjectionSQLReasonCurrentRecovery},
		{"source-current", ownerProjectionSQLReasonCurrentSource},
		{"source-interval", ownerProjectionSQLReasonCurrentInterval},
		{"cancelled", ownerProjectionSQLReasonCurrentCancelled},
		{"query", ownerProjectionSQLReasonCurrentQuery},
		{"administrator-identity", ownerProjectionSQLReasonCurrentAdministratorIdentity},
		{"query-result", ownerProjectionSQLReasonCurrentQueryResult},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &ownerProjectionReasonContext{Context: context.Background()}
			q := &ownerPrerequisiteQuery{administrator: 10, aggregate: true, fields: [6]bool{true, true, true, true, true, true}}
			switch tc.name {
			case "query":
				q.failure = ownerProjectionPrivateDiagnosticError{}
			case "cancelled":
				q.afterRead = func() { ctx.failure = context.Canceled }
			case "administrator-identity":
				q.administrator++
			case "query-result":
				q.aggregate = false
			default:
				i := map[string]int{"administrator": 0, "schema": 1, "activation": 2, "recovery": 3, "source-current": 4, "source-interval": 5}[tc.name]
				q.fields[i], q.aggregate = false, false
			}
			s := &OwnerIdentitySQLRoles{administrator: 10}
			_, _, err := s.current(ctx, q)
			times := 0
			reason := ownerProjectionFinalCurrentReason(ctx, err, time.Time{}, func() time.Time { times++; return time.Time{} })
			if reason != tc.want || q.calls != 1 || ctx.reads != 1 || times != 0 {
				t.Fatal("existing SQL prerequisite was replaced or resampled", reason, q.calls, ctx.reads, times)
			}
			failure := &OwnerProjectionSQLFailure{check: ownerProjectionSQLCurrentAfterFinal, reason: reason, cause: cfg.ErrUnavailable}
			if !errors.Is(failure, cfg.ErrUnavailable) || failure.Reason() != tc.want || failure.Check() != ownerProjectionSQLCurrentAfterFinal || failure.Unwrap() != cfg.ErrUnavailable {
				t.Fatal("current-after-final public normalization changed")
			}
		})
	}
}

func TestOwnerProjectionFinalCurrentReasonRejectsUnknownAndPrivateText(t *testing.T) {
	const private = "synthetic-private-password-and-driver-query"
	for _, current := range []error{errors.New(private), ownerIdentityPrerequisiteError(private), ownerProjectionPrivateDiagnosticError{}} {
		reason := ownerProjectionFinalCurrentReason(nil, current, time.Time{}, nil)
		failure := &OwnerProjectionSQLFailure{check: ownerProjectionSQLCurrentAfterFinal, reason: reason, cause: cfg.ErrUnavailable}
		if reason != ownerProjectionSQLReasonCurrentUnknown || strings.Contains(failure.Error(), private) || failure.Unwrap() != cfg.ErrUnavailable {
			t.Fatal("unknown prerequisite escaped closed normalization")
		}
	}
	seen := map[string]bool{}
	for reason := ownerProjectionSQLReasonUnspecified; reason <= ownerProjectionSQLReasonDeadline; reason++ {
		value := reason.String()
		if value == "unknown" || seen[value] {
			t.Fatal("reason vocabulary is ambiguous", value)
		}
		seen[value] = true
	}
	unknown := &OwnerProjectionSQLFailure{check: OwnerProjectionSQLCheck(255), reason: OwnerProjectionSQLReason(255), cause: cfg.ErrUnavailable}
	if unknown.Error() != "owner projection SQL: unknown: unknown" || !errors.Is(unknown, cfg.ErrUnavailable) {
		t.Fatal("unknown numeric diagnostics rendered an arbitrary value")
	}
	prior := &OwnerProjectionSQLFailure{check: ownerProjectionSQLCommit, cause: cfg.ErrUnavailable}
	if prior.Reason() != ownerProjectionSQLReasonUnspecified || prior.Error() != "owner projection SQL: commit" {
		t.Fatal("other original SQL stages changed diagnostics")
	}
}
