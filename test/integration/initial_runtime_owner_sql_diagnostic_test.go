package integration

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type ownerSQLPrerequisites struct {
	At                                                                   time.Time
	Administrative, Primary, Schema, Activation, Claim, Audit, Activated bool
	Trust, Unsuspended, Recovery, NotFuture, Unexpired, Interval         bool
	ObservedAt, FreshUntil                                               pgtype.Timestamptz
}

func (v ownerSQLPrerequisites) stable() bool {
	return v.Administrative && v.Primary && v.Schema && v.Activation && v.Claim && v.Audit && v.Activated && v.Trust && v.Recovery && v.NotFuture && v.Interval
}
func (v ownerSQLPrerequisites) current() bool { return v.stable() && v.Unsuspended && v.Unexpired }

type ownerSQLDiagnosticQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
