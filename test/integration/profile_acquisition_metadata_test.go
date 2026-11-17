package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each entry owns the existing pristine protected SQL/S3 fixture. Human,
// endpoint and process observations remain explicit synthetic component facts.
func TestVerifiedProfileAcquisitionWithRealPostgres(t *testing.T) {
	qualifyProfileAcquisitionFixture(t, false)
}

func TestLegacyProfileAcquisitionWithRealPostgres(t *testing.T) {
	qualifyProfileAcquisitionFixture(t, true)
}

func qualifyProfileAcquisitionFixture(t *testing.T, legacy bool) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, objects *objectstore.AuthorityObjects) {
		t.Run("profile-acquisition-publication", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, objects, func(t *testing.T, f *queryLedgerFixture) {
				if !legacy {
				}
			}, true, false, legacy)
		})
	})
}

// qualifyProfileAcquisitionAfterPublication checks the window the producer
// reported with its stored outcome (REQ-EVD-001) on the joined catalog read.
// legacy models a catalog row published before windows were recorded.
func qualifyProfileAcquisitionAfterPublication(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, e artifact.ContextExpectation, expected artifact.AcquisitionWindow, legacy bool) {
	t.Helper()
	ctx := f.ctx
	qualifyProfileAcquisitionSQLPair(t, f, e.CaptureUID)
	if legacy {
		if _, err := f.admin.Exec(ctx, "UPDATE context_catalog SET acquisition_started_at=NULL,acquisition_completed_at=NULL WHERE capture_id=$1", e.CaptureUID); err != nil {
			t.Fatal("legacy catalog fixture", err)
		}
	}
	pool := f.fixturePool("context_catalog_read_runtime", "synthetic-context-read")
	defer pool.Close()
	catalog, err := postgres.NewContextPublications(ctx, pool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil || metadata.ProfileAcquisition == nil {
		t.Fatal("joined catalog lost profile acquisition metadata", err)
	}
	p := metadata.ProfileAcquisition
	if p.Type != e.Profile.Type || p.Mode != e.Profile.Mode || p.DurationMillis != e.Profile.DurationMillis || p.ForceGC != e.Profile.ForceGC || (p.Acquisition == nil) != legacy || p.Acquisition != nil && !p.Acquisition.Equal(expected) {
		t.Fatal("joined catalog changed accepted parameters or producer window", p)
	}
	progressPool := f.fixturePool("context_progress_read_runtime", "synthetic-context-progress-read")
	defer progressPool.Close()
	progress, err := postgres.NewContextProgressReads(ctx, progressPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	request := progressQuery(t, ctx, s)
	result, err := progress.ReadContextProgress(ctx, request)
	if err != nil || result.Phase != "Succeeded" {
		t.Fatal("progress failed acquisition audit reconstruction", result, err)
	}
	// This direct admission fixture does not publish encrypted capture-history
	// parameters, so it cannot qualify list_capture_history visibility. Exercise
	// the actual history-facts query using its normal read role and compare the
	// exact shared input that historyEntries casts into progressFacts above.
	var rootID, captureID pgtype.UUID
	if rootID.Scan(s.a.RootID) != nil || captureID.Scan(e.CaptureUID) != nil {
		t.Fatal("profile history-facts fixture identifiers")
	}
	queries := custodydb.New(progressPool)
	history, err := queries.ReadCaptureHistoryFacts(ctx, custodydb.ReadCaptureHistoryFactsParams{RootID: rootID, Ids: []pgtype.UUID{captureID}})
	if err != nil || len(history) != 1 {
		t.Fatal("history acquisition facts unavailable", len(history), err)
	}
	current, err := queries.ReadContextProgressFacts(ctx, custodydb.ReadContextProgressFactsParams{RootID: rootID, ID: captureID})
	if err != nil || !reflect.DeepEqual(custodydb.ReadContextProgressFactsRow(history[0]), current) {
		t.Fatal("history facts differ from the validated progress audit reconstruction", err)
	}
	t.Logf("actual published profile acquisition: catalog/progress/history-facts parity; legacy unknown=%t; no history-parameter publication, native endpoint or process-attribution qualification", legacy)
}

func qualifyProfileAcquisitionSQLPair(t *testing.T, f *capacitySQLFixture, captureID string) {
	t.Helper()
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Exercise the catalog's window CHECK on a temporary copy of the row.
	if _, err := tx.Exec(f.ctx, "CREATE TEMP TABLE acquisition_pair_probe (LIKE context_catalog INCLUDING CONSTRAINTS) ON COMMIT DROP"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, "INSERT INTO acquisition_pair_probe SELECT * FROM context_catalog WHERE capture_id=$1", captureID); err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{"acquisition_started_at=NULL", "acquisition_completed_at=NULL", "acquisition_completed_at=acquisition_started_at-interval '1 microsecond'", "acquisition_started_at='infinity'", "acquisition_completed_at='infinity'"} {
		if _, err := tx.Exec(f.ctx, "SAVEPOINT invalid_pair"); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(f.ctx, "UPDATE acquisition_pair_probe SET "+set)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("acquisition SQL pair CHECK did not reject", set, err)
		}
		if _, err := tx.Exec(f.ctx, "ROLLBACK TO SAVEPOINT invalid_pair"); err != nil {
			t.Fatal(err)
		}
	}
}
