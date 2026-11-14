package postgres

import (
	"context"
	"errors"
	"time"

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
