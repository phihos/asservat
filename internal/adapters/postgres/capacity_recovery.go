package postgres

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// capacityTrustJSON returns the current trust wire that the capacity SQL
// functions still read as their recovery argument.
func capacityTrustJSON(ctx context.Context, q *custodydb.Queries, installation string) ([]byte, error) {
	_, wire, err := currentTrust(ctx, q, installation)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

// capacityObservationJSON encodes o with the current trust wire under the
// "Recovery" key that the capacity SQL functions still read.
func capacityObservationJSON(ctx context.Context, q *custodydb.Queries, installation string, o any, limit int) ([]byte, error) {
	wire, err := capacityTrustJSON(ctx, q, installation)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, cfg.ErrUnavailable
	}
	fields["Recovery"] = wire
	out, err := json.Marshal(fields)
	if err != nil || len(out) > limit {
		return nil, cfg.ErrUnavailable
	}
	return out, nil
}
