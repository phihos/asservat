package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The two concrete facets retain separate fixed-purpose credentials. Their
// constructors do not create a root, discover a login or accept a qualification.
// Each RPC independently checks the exact already pinned login OID in SQL.
type CapacityEnrollments struct{ read capacityEnrollmentReader }
type CapacityCaptureEnrollments struct{ read capacityEnrollmentReader }

type capacityEnrollmentReader struct {
	ledger             *Ledger
	root, installation string
	accounts           app.CaptureAccounts
	capture            bool
}

func NewCapacityEnrollments(ctx context.Context, pool *pgxpool.Pool, root, installation string, accounts app.CaptureAccounts) (*CapacityEnrollments, error) {
	r, e := newCapacityEnrollmentReader(ctx, pool, root, installation, accounts, false)
	if e != nil {
		return nil, e
	}
	return &CapacityEnrollments{read: r}, nil
}
func NewCapacityCaptureEnrollments(ctx context.Context, pool *pgxpool.Pool, root, installation string, accounts app.CaptureAccounts) (*CapacityCaptureEnrollments, error) {
	r, e := newCapacityEnrollmentReader(ctx, pool, root, installation, accounts, true)
	if e != nil {
		return nil, e
	}
	return &CapacityCaptureEnrollments{read: r}, nil
}
func newCapacityEnrollmentReader(ctx context.Context, pool *pgxpool.Pool, root, installation string, accounts app.CaptureAccounts, capture bool) (capacityEnrollmentReader, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || accounts == nil || !identity.Text(accounts.AccountVersion(), 64) {
		return capacityEnrollmentReader{}, cfg.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return capacityEnrollmentReader{}, e
	}
	return capacityEnrollmentReader{ledger: l, root: root, installation: installation, accounts: accounts, capture: capture}, nil
}
func (s *CapacityEnrollments) ReadCapacityEnrollment(ctx context.Context, o app.EnrollmentObservation) (*app.Enrollment, error) {
	if s == nil {
		return nil, cfg.ErrUnavailable
	}
	return s.read.current(ctx, o)
}

// Used before the capture-only transition, including exact recovery of its
// earlier unknown SQL reply. This is not an account-creation fallback.
func (s *CapacityCaptureEnrollments) ReadCapacityEnrollment(ctx context.Context, o app.EnrollmentObservation) (*app.Enrollment, error) {
	if s == nil {
		return nil, cfg.ErrUnavailable
	}
	return s.read.current(ctx, o)
}

func (s *capacityEnrollmentReader) current(ctx context.Context, o app.EnrollmentObservation) (*app.Enrollment, error) {
	if s == nil || s.ledger == nil || s.accounts == nil || ctx == nil || ctx.Err() != nil || o.Key.RootID != s.root || o.Recovery.InstallationID != s.installation || !o.Valid(time.Now()) || o.Plan.AccountVersion() != s.accounts.AccountVersion() {
		return nil, cfg.ErrUnavailable
	}
	plan, pool, source, e := o.Plan.CanonicalValues()
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	observation, e := json.Marshal(o)
	if e != nil || len(observation) > 128<<10 {
		return nil, cfg.ErrUnavailable
	}
	// The immutable plan is transmitted directly, never reconstructed by a
	// caller-selected digest or an ephemeral process-local plan lookup.
	until := o.FreshUntil
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	var out capacityEnrollmentRead
	var narrow *time.Timer
	var joined chan struct{}
	defer func() {
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
	}()
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		var raw []byte
		var err error
		if s.capture {
			raw, err = q.ReadCapacityCaptureEnrollment(live, custodydb.ReadCapacityCaptureEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source})
		} else {
			raw, err = q.ReadCapacityEnrollment(live, custodydb.ReadCapacityEnrollmentParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, SourceCanonical: source})
		}
		if err != nil {
			return err
		}
		out, err = decodeCapacityEnrollment(raw)
		if err != nil || !out.matches(o, time.Now()) {
			return cfg.ErrUnavailable
		}
		if out.Enrollment != nil {
			digest, err := s.accounts.CaptureAccount(s.root, out.Enrollment.AllocationID)
			if err != nil || digest != out.Enrollment.AccountDigest {
				return cfg.ErrUnavailable
			}
		}
		until = identity.Earlier(until, out.FreshUntil)
		if live.Err() != nil || !time.Now().Before(until) {
			return cfg.ErrUnavailable
		}
		// The transaction's commit uses live as well. SQL can discover a shorter
		// permission/source interval after locks; it must cancel that commit,
		// not merely make a successful effect look unavailable afterward.
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
		if live.Err() != nil || !time.Now().Before(until) {
			return cfg.ErrUnavailable
		}
		done := make(chan struct{})
		joined = done
		narrow = time.AfterFunc(time.Until(until), func() { end(); close(done) })
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) || !out.matches(o, time.Now()) {
		return nil, cfg.ErrUnavailable
	}
	return out.Enrollment, nil
}
