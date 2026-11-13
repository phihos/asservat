package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CapacityInitialization is the capacity root's original input: the control
// cluster and namespace, the deterministic source digest, the capture account
// version and the qualification built from the Helm capacity settings.
type CapacityInitialization struct {
	ClusterID, NamespaceUID string
	SourceDigest            artifact.Digest
	AccountVersion          string
	Qualification           app.CapacityQualification
}

// CapacityInitialized is what InitializeCapacity found or did.
type CapacityInitialized string

const (
	CapacityCreated CapacityInitialized = "created"
	CapacityPresent CapacityInitialized = "present"
	// CapacityDifferent: a root exists with other inputs; it stays in effect.
	CapacityDifferent CapacityInitialized = "different"
)

// ErrCapacityPermissionPending is the retryable refusal before the permission
// stream is current or before the setup roles exist.
var ErrCapacityPermissionPending = errors.New("capacity initialization pending")

// InitializeCapacity inserts the capacity root pair once through migration
// 00156's initialize_capacity_source, with the capacity login (role 70). A
// present root is never changed.
func InitializeCapacity(ctx context.Context, pool *pgxpool.Pool, in CapacityInitialization) (CapacityInitialized, error) {
	q := in.Qualification
	if ctx == nil || ctx.Err() != nil || pool == nil || !authorization.UUID(in.ClusterID) || !identity.Text(in.NamespaceUID, 64) || in.SourceDigest == (artifact.Digest{}) ||
		!identity.Text(in.AccountVersion, 64) || !q.Valid() || !app.ValidateRootBackingInput(q.RootBacking) || q.RootBacking.AccountVersion != in.AccountVersion {
		return "", cfg.ErrInvalid
	}
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 128<<10 {
		return "", cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var out string
	err = pool.QueryRow(call, `SELECT public.initialize_capacity_source($1,$2,$3,$4,$5,$6::jsonb)`,
		q.RootBacking.RootID, in.ClusterID, in.NamespaceUID, in.SourceDigest[:], in.AccountVersion, raw).Scan(&out)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "55000" {
			return "", ErrCapacityPermissionPending
		}
		return "", cfg.ErrUnavailable
	}
	switch v := CapacityInitialized(out); v {
	case CapacityCreated, CapacityPresent, CapacityDifferent:
		return v, nil
	}
	return "", cfg.ErrUnavailable
}

// ErrCapacityQualificationAbsent: the permission root has no capacity root
// yet (read_capacity_qualification returned NULL).
var ErrCapacityQualificationAbsent = errors.New("capacity root not initialized")

// ReadCapacityQualification reads the stored qualification of a permission
// root; ErrCapacityQualificationAbsent when the root is not initialized.
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
