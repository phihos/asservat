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
	cfg "asservat.local/asservat/internal/domain/configuration"
)

var _ app.CapacityRecoveryReader = (*CapacitySourceJournal)(nil)

func decodeCapacityRecovery(raw []byte) (artifact.RecoveryProof, error) {
	var out artifact.RecoveryProof
	if len(raw) < 2 || len(raw) > 4096 {
		return out, cfg.ErrUnavailable
	}
	value := jsontext.Value(bytes.Clone(raw))
	if value.Canonicalize() != nil {
		return out, cfg.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return artifact.RecoveryProof{}, cfg.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return artifact.RecoveryProof{}, cfg.ErrUnavailable
	}
	encoded, err := json.Marshal(out)
	if err != nil || !capacitySameJSONFields(raw, encoded) {
		return artifact.RecoveryProof{}, cfg.ErrUnavailable
	}
	return out, nil
}

// RecoveryState is the capacity credential's closed read-only observation. It
// uses the original installed root association; it neither accepts recovery
// nor gives this role general SELECT on fleet or permission state.
func (s *CapacitySourceJournal) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	var zero artifact.RecoveryProof
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	started := capacityObservedMicro(time.Now().UTC())
	until := started.Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	until = until.Truncate(time.Microsecond)
	if !until.After(started) {
		return zero, cfg.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	var out artifact.RecoveryProof
	var narrow *time.Timer
	var joined chan struct{}
	defer func() {
		if narrow != nil && !narrow.Stop() {
			<-joined
		}
	}()
	err := s.ledger.transaction(live, func(q *custodydb.Queries) error {
		raw, err := q.ReadCapacityRecovery(live, custodydb.ReadCapacityRecoveryParams{RootID: id(s.root), ObservedAt: ts(started), FreshUntil: ts(until)})
		if err != nil {
			return err
		}
		out, err = decodeCapacityRecovery(raw)
		if err != nil || out.InstallationID != s.installation || !out.Valid(time.Now()) || !out.ObservedAt.Equal(started) || out.FreshUntil.After(until) || live.Err() != nil {
			return cfg.ErrUnavailable
		}
		until = out.FreshUntil
		joined = make(chan struct{})
		narrow = time.AfterFunc(time.Until(until), func() { end(); close(joined) })
		// Even the read-only commit retains the narrower returned bound. The
		// cancellation owner is joined before this method returns a proof.
		return nil
	})
	if err != nil || live.Err() != nil || !out.Valid(time.Now()) || !time.Now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
