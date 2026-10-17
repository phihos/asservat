package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

type ownerPrerequisiteQuery struct {
	fields        [6]bool
	administrator uint32
	aggregate     bool
	calls         int
	failure       error
	afterRead     func()
}

func (q *ownerPrerequisiteQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected diagnostic query")
}
func (q *ownerPrerequisiteQuery) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	q.calls++
	return functionIdentityRow(func(dst ...any) error {
		if q.failure != nil {
			return q.failure
		}
		*dst[0].(*uint32) = 42
		*dst[1].(*time.Time) = time.Date(2026, 10, 13, 12, 0, 0, 0, time.FixedZone("fixture", 3600))
		*dst[2].(*uint32) = q.administrator
		*dst[3].(*bool) = q.aggregate
		for i, v := range q.fields {
			if i+4 < len(dst) {
				*dst[i+4].(*bool) = v
			}
		}
		if q.afterRead != nil {
			q.afterRead()
		}
		return nil
	})
}

func TestOwnerIdentitySQLPrerequisiteParityAndSingleQuery(t *testing.T) {
	for mask := 0; mask < 64; mask++ {
		q := &ownerPrerequisiteQuery{administrator: 10, aggregate: true}
		for i := range q.fields {
			q.fields[i] = mask&(1<<i) != 0
			q.aggregate = q.aggregate && q.fields[i]
		}
		s := &OwnerIdentitySQLRoles{administrator: 10}
		database, postmaster, err := s.current(context.Background(), q)
		if (err == nil) != q.aggregate || q.calls != 1 {
			t.Fatalf("predicate conjunction changed mask=%d calls=%d", mask, q.calls)
		}
		if err != nil && (!errors.Is(err, cfg.ErrUnavailable) || database != 0 || !postmaster.IsZero()) {
			t.Fatal("denied predicate returned authority or changed sentinel")
		}
		if err == nil && (database != 42 || postmaster.Location() != time.UTC) {
			t.Fatal("positive current identity changed")
		}
	}
}

func TestOwnerIdentitySQLPrerequisiteErrorsStaySanitized(t *testing.T) {
	for _, mode := range []string{"query", "cancelled", "administrator-identity", "query-result", "schema", "activation", "recovery", "source-current", "source-interval", "administrator"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := &ownerPrerequisiteQuery{administrator: 10, aggregate: true, fields: [6]bool{true, true, true, true, true, true}}
			switch mode {
			case "query":
				q.failure = errors.New("synthetic secret=must-never-escape")
			case "cancelled":
				q.afterRead = cancel
			case "administrator-identity":
				q.administrator = 11
			case "query-result":
				q.aggregate = false
			default:
				i := map[string]int{"administrator": 0, "schema": 1, "activation": 2, "recovery": 3, "source-current": 4, "source-interval": 5}[mode]
				q.fields[i] = false
				q.aggregate = false
			}
			s := &OwnerIdentitySQLRoles{administrator: 10}
			_, _, err := s.current(ctx, q)
			if !errors.Is(err, cfg.ErrUnavailable) || err.Error() != "owner identity SQL prerequisite unavailable: "+mode || strings.Contains(err.Error(), "must-never-escape") || q.calls != 1 {
				t.Fatal("fixed diagnostic/sentinel mismatch", mode)
			}
		})
	}
}
