package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The general and capture facets are deliberately different exported types.
// The runtime loader supplies their two different fixed-purpose credentials.
type CapacityRootBacking struct{ scope capacityRootScope }
type CapacityRootCaptureBacking struct{ scope capacityRootScope }
type capacityRootScope struct {
	ledger                            *Ledger
	root, installation, qualification string
	digest                            artifact.Digest
}

var _ app.CapacityRootStore = (*CapacityRootBacking)(nil)
var _ app.CapacityRootCapture = (*CapacityRootCaptureBacking)(nil)

func newCapacityRootScope(ctx context.Context, pool *pgxpool.Pool, root, installation, qualification string, digest artifact.Digest) (capacityRootScope, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !authorization.UUID(qualification) || digest == (artifact.Digest{}) {
		return capacityRootScope{}, cfg.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return capacityRootScope{}, e
	}
	return capacityRootScope{l, root, installation, qualification, digest}, nil
}
func NewCapacityRootBacking(ctx context.Context, pool *pgxpool.Pool, root, installation, qualification string, digest artifact.Digest) (*CapacityRootBacking, error) {
	s, e := newCapacityRootScope(ctx, pool, root, installation, qualification, digest)
	if e != nil {
		return nil, e
	}
	return &CapacityRootBacking{s}, nil
}
func NewCapacityRootCaptureBacking(ctx context.Context, pool *pgxpool.Pool, root, installation, qualification string, digest artifact.Digest) (*CapacityRootCaptureBacking, error) {
	s, e := newCapacityRootScope(ctx, pool, root, installation, qualification, digest)
	if e != nil {
		return nil, e
	}
	return &CapacityRootCaptureBacking{s}, nil
}

type capacityRootResult struct {
	Configuration *app.RootConfiguration
	FreshUntil    time.Time
}

func decodeCapacityRootResult(raw []byte) (capacityRootResult, error) {
	var out capacityRootResult
	if len(raw) < 2 || len(raw) > 16<<10 {
		return out, cfg.ErrUnavailable
	}
	v := jsontext.Value(bytes.Clone(raw))
	if v.Canonicalize() != nil {
		return out, cfg.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return out, cfg.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return out, cfg.ErrUnavailable
	}
	encoded, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, encoded) || out.FreshUntil.IsZero() || out.FreshUntil.Nanosecond()%1000 != 0 || out.Configuration != nil && !out.Configuration.Valid() {
		return capacityRootResult{}, cfg.ErrUnavailable
	}
	return out, nil
}

func (s *CapacityRootBacking) ReadCapacityRoot(ctx context.Context, o app.RootBackingObservation) (*app.RootConfiguration, error) {
	if s == nil {
		return nil, cfg.ErrUnavailable
	}
	return s.scope.run(ctx, o, nil, "read")
}
func (s *CapacityRootBacking) ReserveCapacityRoot(ctx context.Context, o app.RootBackingObservation) (app.RootConfiguration, error) {
	if s == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	v, e := s.scope.run(ctx, o, nil, "reserve")
	if e != nil || v == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	return *v, nil
}
func (s *CapacityRootBacking) RenewCapacityRoot(ctx context.Context, o app.RootBackingObservation, expected app.RootConfiguration) (app.RootConfiguration, error) {
	if s == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	v, e := s.scope.run(ctx, o, &expected, "renew")
	if e != nil || v == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	return *v, nil
}

func (s *CapacityRootBacking) PublishCapacityRoot(ctx context.Context, o app.RootBackingObservation, expected app.RootConfiguration) (app.RootConfiguration, error) {
	if s == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	v, e := s.scope.run(ctx, o, &expected, "publish")
	if e != nil || v == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	return *v, nil
}
func (s *CapacityRootCaptureBacking) BackCapacityRoot(ctx context.Context, o app.RootBackingObservation, expected app.RootConfiguration) (app.RootConfiguration, error) {
	if s == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	v, e := s.scope.run(ctx, o, &expected, "capture")
	if e != nil || v == nil {
		return app.RootConfiguration{}, cfg.ErrUnavailable
	}
	return *v, nil
}

func (s *capacityRootScope) run(ctx context.Context, o app.RootBackingObservation, expected *app.RootConfiguration, phase string) (*app.RootConfiguration, error) {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !o.Valid(time.Now()) || o.RootID != s.root || o.InstallationID != s.installation || o.QualificationID != s.qualification || o.QualificationDigest != s.digest {
		return nil, cfg.ErrUnavailable
	}
	if expected != nil && (!expected.Valid() || expected.RootID != s.root || expected.PlanDigest != o.PlanDigest) {
		return nil, cfg.ErrUnavailable
	}
	if (phase == "capture" || phase == "publish" || phase == "renew") != (expected != nil) {
		return nil, cfg.ErrUnavailable
	}
	observation, e := json.Marshal(o)
	if e != nil || len(observation) > 16<<10 {
		return nil, cfg.ErrUnavailable
	}
	plan, pool := o.CanonicalValues()
	var prior []byte
	if expected != nil {
		prior, e = json.Marshal(expected)
		if e != nil || len(prior) > 8192 {
			return nil, cfg.ErrUnavailable
		}
	}
	until := o.FreshUntil
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	var out capacityRootResult
	var timer *time.Timer
	var joined chan struct{}
	defer func() {
		if timer != nil && !timer.Stop() {
			<-joined
		}
	}()
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		var raw []byte
		var err error
		switch phase {
		case "read":
			raw, err = q.ReadCapacityRoot(live, custodydb.ReadCapacityRootParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool})
		case "reserve":
			attempt, e := uuid.NewRandom()
			if e != nil {
				return cfg.ErrUnavailable
			}
			raw, err = q.ReserveCapacityRoot(live, custodydb.ReserveCapacityRootParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, AttemptID: id(attempt.String())})
		case "renew":
			raw, err = q.RenewCapacityRoot(live, custodydb.RenewCapacityRootParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, ExpectedValue: prior})
		case "capture":
			raw, err = q.BackCapacityRoot(live, custodydb.BackCapacityRootParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, ExpectedValue: prior})
		case "publish":
			raw, err = q.PublishCapacityRoot(live, custodydb.PublishCapacityRootParams{RootID: id(s.root), ObservationValue: observation, PlanCanonical: plan, PoolCanonical: pool, ExpectedValue: prior})
		default:
			return cfg.ErrUnavailable
		}
		if err != nil {
			return err
		}
		out, err = decodeCapacityRootResult(raw)
		if err != nil || out.FreshUntil.After(until) || out.Configuration == nil && phase != "read" || out.Configuration != nil && (out.Configuration.RootID != s.root || out.Configuration.PlanDigest != o.PlanDigest) || expected != nil && (out.Configuration == nil || phase == "renew" && !expected.CompatibleRenewal(*out.Configuration, o) || phase != "renew" && !expected.CompatibleContinuation(*out.Configuration)) {
			return cfg.ErrUnavailable
		}
		until = identity.Earlier(until, out.FreshUntil)
		if live.Err() != nil || !time.Now().Before(until) || !o.Valid(time.Now()) {
			return cfg.ErrUnavailable
		}
		joined = make(chan struct{})
		timer = time.AfterFunc(time.Until(until), func() { end(); close(joined) })
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) || !o.Valid(time.Now()) {
		return nil, cfg.ErrUnavailable
	}
	return out.Configuration, nil
}
