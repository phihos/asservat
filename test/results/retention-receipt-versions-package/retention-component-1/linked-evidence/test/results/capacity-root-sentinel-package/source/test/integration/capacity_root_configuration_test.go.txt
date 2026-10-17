package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type capacityRootDigestCase struct {
	name  string
	body  map[string]any
	valid bool
	typed bool
}

// These are validator inputs only, never persisted or used as source authority.
// The actual three-phase fixture still obtains every original date from SQL.
func capacityRootDigestCases(t *testing.T) []capacityRootDigestCase {
	t.Helper()
	n := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	initial := app.RootConfiguration{
		Format:     app.RootConfigurationFormat,
		RootID:     "30000000-0000-4000-8000-000000000001",
		AttemptID:  "30000000-0000-4000-8000-000000000002",
		PlanDigest: artifact.Digest{1}, Revision: 1,
		InitialObservedAt: n, InitialUntil: n.Add(5 * time.Second),
		RevisionObservedAt: n, RevisionUntil: n.Add(5 * time.Second),
		PlannedUntil: n.Add(time.Hour), ReservedAt: n.Add(time.Second),
	}
	object := func(v app.RootConfiguration) map[string]any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err = json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	var cases []capacityRootDigestCase
	add := func(name string, v app.RootConfiguration, valid bool) {
		cases = append(cases, capacityRootDigestCase{name: name, body: object(v), valid: valid, typed: true})
	}
	add("initial-zero-phase-sentinels", initial, true)
	captureAt, readyAt, closedAt := n.Add(2*time.Second), n.Add(3*time.Second), n.Add(time.Hour)
	backed := initial
	backed.CaptureBackedAt = &captureAt
	add("capture-backed-still-unreconciled", backed, true)
	ready := backed
	ready.ReadyAt = &readyAt
	add("ready-still-unreconciled", ready, true)
	closed := ready
	closed.ReconciledAt, closed.ReconciledDigest = &closedAt, artifact.Digest{2}
	add("positive-original-disposition", closed, true)
	renewed := initial
	renewed.Revision, renewed.PreviousDigest = 2, closed.ReconciledDigest
	renewed.RevisionObservedAt = closedAt
	renewed.RevisionUntil = closedAt.Add(5 * time.Second)
	renewed.ReservedAt, renewed.PlannedUntil = closedAt.Add(time.Second), closedAt.Add(time.Hour)
	add("renewed-positive-predecessor-zero-disposition", renewed, true)
	maximum := renewed
	for i := range maximum.PreviousDigest {
		maximum.PreviousDigest[i] = 255
	}
	add("maximum-valid-predecessor-bytes", maximum, true)
	v := initial
	v.PreviousDigest = artifact.Digest{3}
	add("initial-cannot-have-predecessor", v, false)
	v = renewed
	v.PreviousDigest = artifact.Digest{}
	add("renewal-requires-predecessor", v, false)
	v = closed
	v.ReconciledDigest = artifact.Digest{}
	add("time-cannot-manufacture-disposition", v, false)
	v = initial
	v.ReconciledDigest = artifact.Digest{3}
	add("digest-cannot-manufacture-reconciled-time", v, false)
	for _, field := range []string{"PreviousDigest", "ReconciledDigest"} {
		for _, name := range []string{"missing", "null", "string", "object", "short", "long", "string-byte", "null-byte", "boolean-byte", "negative-byte", "oversize-byte", "fractional-byte"} {
			body := object(initial)
			bytes := body[field].([]any)
			switch name {
			case "missing":
				delete(body, field)
			case "null":
				body[field] = nil
			case "string":
				body[field] = "0000"
			case "object":
				body[field] = map[string]any{}
			case "short":
				body[field] = bytes[:31]
			case "long":
				body[field] = append(bytes, float64(0))
			case "string-byte":
				bytes[0] = "0"
			case "null-byte":
				bytes[0] = nil
			case "boolean-byte":
				bytes[0] = false
			case "negative-byte":
				bytes[0] = float64(-1)
			case "oversize-byte":
				bytes[0] = float64(256)
			case "fractional-byte":
				bytes[0] = 0.5
			}
			cases = append(cases, capacityRootDigestCase{name: field + "-" + name, body: body})
		}
	}
	return cases
}

func TestCapacityRootConfigurationDigestState(t *testing.T) {
	for _, tc := range capacityRootDigestCases(t) {
		if !tc.typed {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			var value app.RootConfiguration
			err = json.Unmarshal(b, &value)
			if got := err == nil && value.Valid(); got != tc.valid {
				t.Fatalf("typed state validity=%v expected=%v error=%v", got, tc.valid, err)
			}
		})
	}
}

func qualifyCapacityRootConfigurationSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	for _, tc := range capacityRootDigestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			var valid bool
			if err = admin.QueryRow(ctx, `SELECT public.capacity_root_configuration_valid($1::jsonb)`, body).Scan(&valid); err != nil {
				t.Fatalf("root state validator unavailable: sqlstate=%s", capacitySQLState(err))
			}
			if valid != tc.valid {
				t.Fatalf("SQL state validity=%v expected=%v", valid, tc.valid)
			}
		})
	}
	t.Run("positive-digest-parser-still-rejects-zero", func(t *testing.T) {
		zero, err := json.Marshal(artifact.Digest{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = admin.Exec(ctx, `SELECT public.connector_digest($1::jsonb)`, zero)
		var driver *pgconn.PgError
		if !errors.As(err, &driver) || driver.Code != "23514" {
			t.Fatalf("positive digest no longer denies zero: sqlstate=%s", capacitySQLState(err))
		}
	})
}
