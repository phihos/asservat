package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	app "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The Helm-values capacity source passes SQL's source validation and pool
// compiler for a best-effort store with a joined cluster (ADR-335 D2).
func TestCapacityValuesSourceWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, _ string, _ *tls.Config, scope fleet.InstallationWitnessScope, _ string, _ fleet.Administration, _ *objectstore.AuthorityObjects) {
		s := &app.ValuesSource{Installation: scope.InstallationID, Cluster: scope.ClusterID, Control: cfg.NamespaceRef{Name: "asservat", UID: scope.NamespaceUID}, Revision: 2,
			Values: app.CapacityValues{EvidenceBytes: 128 << 30, ShareBytes: 16 << 30}, Clusters: []string{scope.ClusterID, custodyID()}, Now: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }}
		o, err := s.ReadCapacitySource(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(o)
		var valid bool
		var slots int64
		if err = admin.QueryRow(ctx, `SELECT public.capacity_source_observation_valid($1::jsonb),COALESCE((public.capacity_compile_pool($1::jsonb,$2)->>'AccountLimit')::bigint,0)`, string(raw), o.Snapshot.Pools[0].Resource.Name).Scan(&valid, &slots); err != nil {
			t.Fatal(err)
		}
		plan, err := app.CompileProtectedPoolPlan(o.Snapshot, o.Snapshot.Pools[0].Resource.Name)
		if err != nil || !valid || slots != plan.AccountLimit || slots != 6 {
			t.Fatal("SQL refused the values source", valid, slots, plan.AccountLimit, err)
		}
	})
}
