package integration

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ownerDeletionAPI struct {
	o      value.OwnerConfigurationObservation
	listed atomic.Int32
	watch  chan string
	delete chan struct{}
}

const (
	ownerBeforeDelete = "1234567890123456789012345678901234567890"
	ownerDeleted      = "1234567890123456789012345678901234567891"
)

func (s *ownerDeletionAPI) OwnerSourceSnapshot(context.Context) (value.OwnerConfigurationObservation, string, error) {
	if s.listed.Add(1) > 1 {
		return value.OwnerConfigurationObservation{}, "", value.ErrUnavailable
	}
	return s.o, ownerBeforeDelete, nil
}
func (s *ownerDeletionAPI) WaitOwnerChange(ctx context.Context, rv string) (string, error) {
	select {
	case s.watch <- rv:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if rv == ownerDeleted {
		return "", value.ErrUnavailable
	}
	select {
	case <-s.delete:
		return ownerDeleted, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func checkOwnerTakeoverAndDeletion(t *testing.T, ctx context.Context, l *ownerConfigLab, current value.OwnerConfiguration) {
	t.Helper()
	next := current.Clone()
	next.Revision.Generation++
	// A new leader sampled its local clock well before the old leader's last
	// observation. Only the newer ConfigMap cursor determines publication order.
	o := value.OwnerConfigurationObservation{Configuration: next, ObservedAt: time.Now().Add(-time.Minute), FreshUntil: time.Now().Add(time.Hour)}
	source := &ownerDeletionAPI{o: o, watch: make(chan string, 2), delete: make(chan struct{})}
	run, cancel := context.WithCancel(ctx)
	worker := app.ConfigurationReconciler{Source: source, Ledger: l.writer}
	done := make(chan error, 1)
	go func() { done <- worker.Run(run) }()
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()
	wait := func(rv string) {
		t.Helper()
		select {
		case got := <-source.watch:
			if got != rv {
				t.Fatalf("cursor %s, expected %s", got, rv)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no owner watch at %s", rv)
		}
	}
	wait(ownerBeforeDelete)
	// Both startup entry points call this same reader and local-time predicate.
	// Shadow only this reader's SQL clock with ordinary PostgreSQL search_path.
	_, err := l.admin.Exec(ctx, `CREATE SCHEMA synthetic_owner_clock;
 CREATE FUNCTION synthetic_owner_clock.clock_timestamp() RETURNS timestamptz
 LANGUAGE sql VOLATILE AS $$ SELECT pg_catalog.clock_timestamp()+interval '500 milliseconds' $$;
 GRANT USAGE ON SCHEMA synthetic_owner_clock TO owner_configuration_read_runtime`)
	if err != nil {
		t.Fatal(err)
	}
	defer l.admin.Exec(context.Background(), "DROP SCHEMA synthetic_owner_clock CASCADE")
	conf := l.readerPool.Config()
	conf.ConnConfig.RuntimeParams["search_path"] = "synthetic_owner_clock,public,pg_catalog"
	skewPool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer skewPool.Close()
	var ahead bool
	if err = skewPool.QueryRow(ctx, "SELECT clock_timestamp()-pg_catalog.clock_timestamp()>interval '490 milliseconds'").Scan(&ahead); err != nil || !ahead {
		t.Fatal("fixture SQL clock offset", ahead, err)
	}
	skew, err := postgres.NewOwnerConfigurations(ctx, skewPool, next.Pool.InstallationID, next.Pool.ClusterID, next.Pool.NamespaceUID, next.Revision.UID)
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []app.OwnerConfigurationReader{l.reader, skew} {
		cfg, err := app.StartupOwnerConfiguration(ctx, reader, next.Pool.Namespace)
		if err != nil || !cfg.Equal(next) {
			t.Fatal("takeover/startup", err)
		}
	}
	// Refuse the first actual SQL fence, then restore its table independently of
	// the dead API. Observe a real attempted UPDATE before letting the retry pass.
	_, err = l.admin.Exec(ctx, fmt.Sprintf(`CREATE SEQUENCE fixture_owner_fence_attempt;
 GRANT USAGE ON SEQUENCE fixture_owner_fence_attempt TO owner_configuration_runtime;
 CREATE FUNCTION fixture_owner_fence_once() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN IF NEW.source_version='%s' AND nextval('fixture_owner_fence_attempt')=1 THEN
 RAISE EXCEPTION 'synthetic transient'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fixture_owner_fence_once BEFORE UPDATE ON hub_owner_configuration FOR EACH ROW EXECUTE FUNCTION fixture_owner_fence_once()`, ownerDeleted))
	if err != nil {
		t.Fatal(err)
	}
	defer l.admin.Exec(context.Background(), "DROP TRIGGER fixture_owner_fence_once ON hub_owner_configuration; DROP FUNCTION fixture_owner_fence_once(); DROP SEQUENCE fixture_owner_fence_attempt")
	close(source.delete)
	wait(ownerDeleted)
	var attempts int
	if err = l.admin.QueryRow(ctx, "SELECT last_value FROM fixture_owner_fence_attempt").Scan(&attempts); err != nil || attempts != 2 {
		t.Fatal("actual fence retries", attempts, err)
	}
	// The watch failed after deletion; every subsequent LIST is unavailable.
	for source.listed.Load() < 2 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err = app.StartupOwnerConfiguration(ctx, skew, next.Pool.Namespace); err == nil {
		t.Fatal("deleted source served during API outage")
	}
	if err = l.writer.ApplyOwnerConfiguration(ctx, ownerBeforeDelete, o); err != nil {
		t.Fatal(err)
	}
	if _, err = l.reader.ReadOwnerConfiguration(ctx); err == nil {
		t.Fatal("delayed pre-deletion cursor restored the owner")
	}
}
