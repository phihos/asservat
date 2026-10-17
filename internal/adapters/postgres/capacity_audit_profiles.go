package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityAuditProfiles has only the fixed read RPC. The installation-owned
// constructor pins prevent a public caller selecting another root or source.
// This credential has no capacity writer, journal or acknowledgement grants.
type CapacityAuditProfiles struct {
	ledger                                            *Ledger
	root, installation, qualification, accountVersion string
	digest                                            artifact.Digest
}

var _ app.CapacityAuditProfiles = (*CapacityAuditProfiles)(nil)

func NewCapacityAuditProfiles(ctx context.Context, pool *pgxpool.Pool, root, installation, qualification string, digest artifact.Digest, accountVersion string) (*CapacityAuditProfiles, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !authorization.UUID(qualification) || digest == (artifact.Digest{}) || !identity.Text(accountVersion, 64) {
		return nil, app.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &CapacityAuditProfiles{l, root, installation, qualification, accountVersion, digest}, nil
}

func decodeCapacityAuditProfiles(raw []byte, now time.Time) (value.AcceptedCapacityAuditProfiles, error) {
	var out value.AcceptedCapacityAuditProfiles
	if len(raw) < 2 || len(raw) > 16<<10 {
		return out, app.ErrUnavailable
	}
	v := jsontext.Value(bytes.Clone(raw))
	if v.Canonicalize() != nil {
		return out, app.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return out, app.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return out, app.ErrUnavailable
	}
	w, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, w) || !out.Valid(now) {
		return value.AcceptedCapacityAuditProfiles{}, app.ErrUnavailable
	}
	return out, nil
}

func (s *CapacityAuditProfiles) ReadCapacityAuditProfiles(ctx context.Context) (value.AcceptedCapacityAuditProfiles, error) {
	var zero value.AcceptedCapacityAuditProfiles
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil {
		return zero, app.ErrUnavailable
	}
	// Narrow, never round up, the original caller interval. Every lock/readback
	// runs inside it; an SQL result may narrow it further but cannot replace it.
	start := time.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d.Truncate(time.Microsecond))
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	var out value.AcceptedCapacityAuditProfiles
	var timer *time.Timer
	var joined chan struct{}
	defer func() {
		if timer != nil && !timer.Stop() {
			<-joined
		}
	}()
	e := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, err := q.ReadCapacityAuditProfiles(live, custodydb.ReadCapacityAuditProfilesParams{RootID: id(s.root), InstallationID: id(s.installation), QualificationID: id(s.qualification), QualificationDigest: s.digest[:], AccountVersion: s.accountVersion, ObservedAt: ts(start), FreshUntil: ts(until)})
		if err != nil {
			return err
		}
		out, err = decodeCapacityAuditProfiles(raw, time.Now())
		if err != nil || out.RootID != s.root || out.InstallationID != s.installation || out.QualificationID != s.qualification || out.QualificationDigest != s.digest || out.AccountVersion != s.accountVersion || !out.ObservedAt.Equal(start) || out.FreshUntil.After(until) {
			return app.ErrUnavailable
		}
		until = identity.Earlier(until, out.FreshUntil)
		if live.Err() != nil || !time.Now().Before(until) {
			return app.ErrUnavailable
		}
		joined = make(chan struct{})
		timer = time.AfterFunc(time.Until(until), func() { end(); close(joined) })
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) || !out.Valid(time.Now()) {
		return zero, app.ErrUnavailable
	}
	return out, nil
}
