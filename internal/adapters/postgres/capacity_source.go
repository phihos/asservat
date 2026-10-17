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
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacitySourceJournal has only fixed RPC authority. The protected setup pins
// both source roles and the qualification in SQL before this constructor runs;
// a successful Ledger constructor or arbitrary CRD assurance string does not.
type CapacitySourceJournal struct {
	ledger                            *Ledger
	root, installation, qualification string
	digest                            artifact.Digest
}

var _ app.CapacitySourceJournal = (*CapacitySourceJournal)(nil)

func NewCapacitySourceJournal(ctx context.Context, pool *pgxpool.Pool, root, installation, qualification string, digest artifact.Digest) (*CapacitySourceJournal, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !authorization.UUID(qualification) || digest == (artifact.Digest{}) {
		return nil, cfg.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &CapacitySourceJournal{l, root, installation, qualification, digest}, nil
}

type capacitySourceAcknowledgement struct {
	Accepted               bool
	Revision               int64
	ObservedAt, FreshUntil time.Time
}

func decodeCapacitySourceAcknowledgement(raw []byte) (capacitySourceAcknowledgement, error) {
	var out capacitySourceAcknowledgement
	if len(raw) < 2 || len(raw) > 1024 {
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
	w, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, w) {
		return out, cfg.ErrUnavailable
	}
	return out, nil
}
func (s *CapacitySourceJournal) ReadCapacitySourceRevision(ctx context.Context, recovery artifact.RecoveryProof) (int64, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || recovery.InstallationID != s.installation || !recovery.Valid(time.Now()) {
		return 0, cfg.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(app.CapacitySourceInterval), recovery.FreshUntil))
	defer end()
	b, e := json.Marshal(recovery)
	if e != nil {
		return 0, cfg.ErrUnavailable
	}
	var revision int64
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		var err error
		revision, err = q.ReadCapacitySourceRevision(live, custodydb.ReadCapacitySourceRevisionParams{RootID: id(s.root), RecoveryValue: b})
		return err
	})
	if e != nil || live.Err() != nil || !recovery.Valid(time.Now()) || revision < 0 || revision >= 1<<60 {
		return 0, cfg.ErrUnavailable
	}
	return revision, nil
}
func (s *CapacitySourceJournal) AcceptCapacitySource(ctx context.Context, in app.CapacitySourceAcceptance) (app.AcceptedCapacitySource, error) {
	var zero app.AcceptedCapacitySource
	if s == nil || ctx == nil || ctx.Err() != nil || !in.Valid(time.Now()) || in.RootID != s.root || in.InstallationID != s.installation || in.QualificationID != s.qualification || in.QualificationDigest != s.digest {
		return zero, cfg.ErrUnavailable
	}
	// PostgreSQL timestamps have microsecond precision. Narrow inputs before
	// serialization so its timestamp parser cannot round a deadline upward.
	in.Observation.Snapshot.ObservedAt = capacityObservedMicro(in.Observation.Snapshot.ObservedAt)
	in.Observation.Snapshot.FreshUntil = in.Observation.Snapshot.FreshUntil.Truncate(time.Microsecond)
	in.Protection.ObservedAt = capacityObservedMicro(in.Protection.ObservedAt)
	in.Protection.FreshUntil = in.Protection.FreshUntil.Truncate(time.Microsecond)
	in.Recovery.ObservedAt = capacityObservedMicro(in.Recovery.ObservedAt)
	in.Recovery.FreshUntil = in.Recovery.FreshUntil.Truncate(time.Microsecond)
	if !in.Valid(time.Now()) {
		return zero, cfg.ErrUnavailable
	}
	until := identity.Earlier(in.Observation.Snapshot.FreshUntil, identity.Earlier(in.Protection.FreshUntil, in.Recovery.FreshUntil))
	live, end := context.WithDeadline(ctx, until)
	defer end()
	observation, e := json.Marshal(in.Observation)
	if e != nil || len(observation) > app.CapacitySourceBytes {
		return zero, cfg.ErrUnavailable
	}
	// Return a snapshot detached from the caller's maps/slices and the serialized
	// input used by SQL. Mutating a later source observation cannot change it.
	var acceptedObservation app.CapacitySourceObservation
	if json.Unmarshal(observation, &acceptedObservation) != nil {
		return zero, cfg.ErrUnavailable
	}
	protection, e := json.Marshal(in.Protection)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	recovery, e := json.Marshal(in.Recovery)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	var ack capacitySourceAcknowledgement
	var narrow *time.Timer
	var joined chan struct{}
	defer func() {
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
	}()
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, err := q.AcceptCapacitySource(live, custodydb.AcceptCapacitySourceParams{RootID: id(s.root), ExpectedRevision: in.ExpectedRevision, ObservationValue: observation, ProtectionValue: protection, RecoveryValue: recovery, QualificationID: id(s.qualification), QualificationDigest: s.digest[:]})
		if err != nil {
			return err
		}
		ack, err = decodeCapacitySourceAcknowledgement(raw)
		if err != nil || ack.Revision < 1 || ack.Revision >= 1<<60 || ack.Revision < in.ExpectedRevision || ack.Revision > in.ExpectedRevision+1 || !ack.Accepted && ack.Revision != in.ExpectedRevision+1 || !identity.Fresh(ack.ObservedAt, ack.FreshUntil, time.Now(), app.CapacitySourceInterval) || ack.FreshUntil.After(until) {
			return cfg.ErrUnavailable
		}
		// SQL may discover a shorter original accepted permission interval. Make
		// it a cancellation bound for the outer transaction's commit as well.
		until = identity.Earlier(until, ack.FreshUntil)
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
		if live.Err() != nil || !time.Now().Before(until) {
			return cfg.ErrUnavailable
		}
		done := make(chan struct{})
		joined = done
		narrow = time.AfterFunc(time.Until(until), func() { end(); close(done) })
		// A well-formed negative acknowledgement must commit its restrictive
		// watermark. Returning unavailable inside this callback would undo it.
		return live.Err()
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) || !ack.Accepted {
		return zero, cfg.ErrUnavailable
	}
	out := app.AcceptedCapacitySource{Format: app.CapacityAcceptedSourceFormat, RootID: s.root, InstallationID: s.installation, QualificationID: s.qualification, QualificationDigest: s.digest, ProtectionDigest: in.Protection.Digest, Revision: ack.Revision, Observation: acceptedObservation, ObservedAt: ack.ObservedAt, FreshUntil: ack.FreshUntil}
	if !out.Valid(time.Now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
func capacityObservedMicro(v time.Time) time.Time {
	t := v.Truncate(time.Microsecond)
	if t.Before(v) {
		return t.Add(time.Microsecond)
	}
	return t
}
func (s *CapacitySourceJournal) InvalidateCapacitySource(ctx context.Context, root string, expected int64, recovery artifact.RecoveryProof, observed, until time.Time) error {
	if s == nil || ctx == nil || ctx.Err() != nil || root != s.root || expected < 0 || expected >= 1<<60 || recovery.InstallationID != s.installation || !recovery.Valid(time.Now()) || !identity.Fresh(observed, until, time.Now(), app.CapacitySourceInterval) {
		return cfg.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, identity.Earlier(until, recovery.FreshUntil))
	defer end()
	b, e := json.Marshal(recovery)
	if e != nil {
		return cfg.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		_, err := q.InvalidateCapacitySource(live, custodydb.InvalidateCapacitySourceParams{RootID: id(root), ExpectedRevision: expected, RecoveryValue: b, ObservedAt: ts(observed), FreshUntil: ts(until)})
		return err
	})
	if e != nil || live.Err() != nil || !identity.Fresh(observed, until, time.Now(), app.CapacitySourceInterval) {
		return cfg.ErrUnavailable
	}
	return nil
}
