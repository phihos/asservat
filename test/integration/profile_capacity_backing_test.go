package integration

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type capacityBackingQueries interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Real PostgreSQL executes the installed immutable compiler; synthetic history
// qualifications here test arithmetic only and grant no product authority.
func TestProfileCapacityBackingWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable", err)
	}
	ctx, end := context.WithTimeout(t.Context(), time.Minute)
	defer end()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	qualifyProfileCapacityParity(t, ctx, admin)
}

func qualifyProfileCapacityParity(t *testing.T, ctx context.Context, q capacityBackingQueries) {
	t.Helper()
	const id = "10000000-0000-4000-8000-000000000001"
	unit := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	r := artifact.Registration{NativeLimit: artifact.MaxGoTraceBytes}
	stream := artifact.StreamingPlan{Registration: r}
	for _, protocol := range []string{"", capacity.ProfileProtocolVersion} {
		h := capacityNativeHistory(id, id)
		h.ProfileProtocol = protocol
		history, _ := json.Marshal(h)
		for _, slice := range []capacity.BudgetAmount{{Bytes: unit, Objects: 4}, {Bytes: unit + 7, Objects: 7}, {Bytes: r.ReservedBytes() + stream.TemporaryBytes(), Objects: int64(5 + stream.PartLimit())}, {Bytes: math.MaxInt64, Objects: math.MaxInt64}} {
			expected, err := capacity.CompileContextProtocolBacking(slice, h)
			if err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(slice)
			var raw []byte
			if err = q.QueryRow(ctx, `SELECT public.capacity_context_protocol_backing($1::jsonb,$2::jsonb)`, input, history).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var actual capacity.ContextProtocolBacking
			if json.Unmarshal(raw, &actual) != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("Go/SQL profile backing mismatch protocol=%q slice=%+v\nGo=%+v\nSQL=%+v", protocol, slice, expected, actual)
			}
			if protocol == "" {
				var same bool
				if err = q.QueryRow(ctx, `SELECT public.capacity_context_protocol_backing($1::jsonb,$2::jsonb)=public.capacity_context_protocol_backing_legacy($1::jsonb,$2::jsonb)`, input, history).Scan(&same); err != nil || !same {
					t.Fatal("legacy funding changed", err)
				}
			}
		}
	}
	h := capacityNativeHistory(id, id)
	h.ProfileProtocol = "unqualified/future"
	history, _ := json.Marshal(h)
	var denied bool
	if err := q.QueryRow(ctx, `SELECT public.capacity_context_protocol_backing('{"Bytes":9999999,"Objects":4}'::jsonb,$1::jsonb) IS NULL`, history).Scan(&denied); err != nil || !denied {
		t.Fatal("unknown profile protocol accepted", err)
	}
}
