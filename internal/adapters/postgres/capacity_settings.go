package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrCapacityQualificationAbsent: the permission root has no capacity settings
// yet (read_capacity_qualification returned NULL).
var ErrCapacityQualificationAbsent = errors.New("capacity root not initialized")

// ErrCapacityPermissionPending is the retryable refusal before the
// permission stream, fleet trust or the setup roles exist.
var ErrCapacityPermissionPending = errors.New("capacity settings pending")

// ApplyCapacity applies the capacity values (capacity_apply). The first call
// creates the root rows from q; later calls change only the values. It
// returns the qualification in effect.
func ApplyCapacity(ctx context.Context, pool *pgxpool.Pool, cluster, namespaceUID string, q app.CapacityQualification, v app.CapacityValues) (app.CapacityQualification, error) {
	var zero app.CapacityQualification
	root := q.RootBacking.RootID
	if ctx == nil || ctx.Err() != nil || pool == nil || !q.Valid() || !v.SettingsValid() || !authorization.UUID(cluster) {
		return zero, cfg.ErrInvalid
	}
	qRaw, err := json.Marshal(q)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	vRaw, err := json.Marshal(v)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	var out []byte
	err = pool.QueryRow(call, `SELECT public.capacity_apply($1,$2,$3,$4,$5::jsonb,$6::jsonb)->'Qualification'`, root, cluster, namespaceUID, q.RootBacking.AccountVersion, qRaw, vRaw).Scan(&out)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && (pg.Code == "55000" || pg.Code == "P0002") {
			return zero, ErrCapacityPermissionPending
		}
		return zero, cfg.ErrUnavailable
	}
	return decodeCapacityQualification(out, root)
}

// ReadCapacityQualification reads the stored qualification of a permission
// root; ErrCapacityQualificationAbsent when it has no capacity settings.
func ReadCapacityQualification(ctx context.Context, pool *pgxpool.Pool, root string) (app.CapacityQualification, error) {
	var zero app.CapacityQualification
	if ctx == nil || ctx.Err() != nil || pool == nil || !authorization.UUID(root) {
		return zero, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var raw []byte
	if err := pool.QueryRow(call, `SELECT public.read_capacity_qualification($1)::text`, root).Scan(&raw); err != nil {
		return zero, cfg.ErrUnavailable
	}
	if raw == nil {
		return zero, ErrCapacityQualificationAbsent
	}
	return decodeCapacityQualification(raw, root)
}

func decodeCapacityQualification(raw []byte, root string) (app.CapacityQualification, error) {
	var out app.CapacityQualification
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || !out.Valid() || !app.ValidateRootBackingInput(out.RootBacking) || out.RootBacking.RootID != root {
		return app.CapacityQualification{}, cfg.ErrUnavailable
	}
	return out, nil
}
