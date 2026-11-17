package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL/S3/Tink, separate SQL roles and full native verification. This fixture
// deliberately synthesizes collector/result/retention authority, not production
// enrollment or permission to enable the public capture workflow.
func qualifyContextPublications(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario, releasePermissionBurst func()) {
	t.Helper()
	readerPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
	defer readerPool.Close()
	if _, err := readerPool.Exec(ctx, "UPDATE context_catalog SET published_at=clock_timestamp()"); err == nil {
		t.Fatal("catalog reader has excess SQL privilege")
	}
	type fixture struct {
		scenario    captureAdmissionScenario
		e           artifact.ContextExpectation
		copies      artifact.Copies
		nativeBytes int64
		reader      *postgres.ContextPublications
		// publish stands in for the stored-outcome transaction (REQ-EVD-001).
		publish func(context.Context) (publishedContext, error)
	}
	var prepareAdmitted func(t *testing.T, ctx context.Context, s captureAdmissionScenario, accepted capture.Accepted, seal evidence.KeySealer, open evidence.KeyOpener, processingCheck func(fixture, *processingTestFixture), initialize bool, shareCohort ...bool) fixture
	shareCaptures := map[string]shareCaptureAudit{}
	// admit, when set, replaces the direct admission (ADR-235 admits a
	// reviewed preview carrying a sharing instruction).
	setupAdmitted := func(t *testing.T, provider func(string) (evidence.KeySealer, evidence.KeyOpener), processingCheck func(fixture, *processingTestFixture), admit func(*testing.T, *captureAdmissionScenario) capture.Accepted, shareCohort ...bool) fixture {
		t.Helper()
		ctx := ctx
		s := create(t, 1)
		if provider != nil {
			// The native source owner starts before processing/crypto/publication,
			// and t.Cleanup joins it even if this setup exits through t.Fatal.
			s.nativeSources = startNativeScenarioSources(t, ctx, admin, s)
			ctx = s.nativeSources.ctx
		}
		var seal evidence.KeySealer = keys
		var open evidence.KeyOpener = keys
		if provider != nil {
			seal, open = provider(s.recovery.installation)
		}
		if admit != nil && len(shareCohort) > 0 && shareCohort[0] {
			qualified := newShareCaptureAudit(t, ctx, admin, poolFor, store, keys, s)
			s.s = qualified.admissions
			shareCaptures[s.a.RootID] = qualified
		}
		var accepted capture.Accepted
		var err error
		if admit != nil {
			accepted = admit(t, &s)
		} else if accepted, err = s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		return prepareAdmitted(t, ctx, s, accepted, seal, open, processingCheck, true, shareCohort...)
	}
	// prepareAdmitted stores, verifies and audits one admitted capture of s so
	// that it is ready to publish. A scenario's processing root is accepted and
	// initialized once (initialize), by its first prepared capture; later
	// captures of the same root are covered by it.
	prepareAdmitted = func(t *testing.T, ctx context.Context, s captureAdmissionScenario, accepted capture.Accepted, seal evidence.KeySealer, open evidence.KeyOpener, processingCheck func(fixture, *processingTestFixture), initialize bool, shareCohort ...bool) fixture {
		t.Helper()
		var err error
		var f fixture
		f.scenario = s
		f.e = accepted.Expectation
		var processing *processingTestFixture
		if initialize {
			processing = newProcessingTestFixture(t, ctx, poolFor, store, keys, s, f.e)
			defer processing.Close()
		}
		if f.reader, err = postgres.NewContextPublications(ctx, readerPool, s.a.RootID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
			t.Fatal("reservation became evidence")
		}
		bound, err := store.ForCustody(f.e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		producer, err := objectstore.NewContextProducer(bound, seal, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := producer.PrepareContext(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		at := time.Now().UTC()
		native, err := json.Marshal(map[string]any{"format": artifact.ContextFormat, "namespaceUID": f.e.NamespaceUID, "podUID": f.e.PodUID, "resourceVersion": "10", "observedAt": at, "phase": "Running", "ready": "True", "initialized": "True", "scheduled": "True", "runtimeInstances": 1, "running": 1, "waiting": 0, "terminated": 0, "restarts": 0})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(native)
		f.nativeBytes = int64(len(native))
		f.copies, err = prepared.StoreContext(ctx, native, at, at)
		if err != nil {
			t.Fatal(err)
		}
		f.publish = func(ctx context.Context) (publishedContext, error) {
			return publishStoredFixture(ctx, admin, f.e, f.copies, f.nativeBytes, nil)
		}
		if processingCheck != nil {
			processingCheck(f, processing)
		}
		return f
	}

	setupWithKeys := func(t *testing.T, provider func(string) (evidence.KeySealer, evidence.KeyOpener), processingCheck func(fixture, *processingTestFixture)) fixture {
		t.Helper()
		return setupAdmitted(t, provider, processingCheck, nil)
	}
	setup := func(t *testing.T) fixture { return setupWithKeys(t, nil, nil) }

	t.Run("published-native-length-and-progress", func(t *testing.T) {
		f := setup(t)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		progressPool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
		defer progressPool.Close()
		progressReader, err := postgres.NewContextProgressReads(ctx, progressPool, f.scenario.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		progress, err := progressReader.ReadContextProgress(ctx, progressQuery(t, ctx, f.scenario))
		if err != nil || progress.Phase != "Succeeded" || progress.ReasonCode != "Published" {
			t.Fatal("published progress", progress, err)
		}
		got, err := f.reader.ContextDownloadEvidence(ctx, f.e.Registration.Location.ArtifactID)
		if err != nil || got.NativeBytes == nil || *got.NativeBytes != f.nativeBytes {
			t.Fatal("catalog lost producer-reported native length", got.NativeBytes, err)
		}
	})

	t.Run("existing-artifact-raw-grants", func(t *testing.T) {
		f := setup(t)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		record, err := f.reader.ContextDownloadEvidence(ctx, f.e.Registration.Location.ArtifactID)
		if err != nil || record.NativeBytes == nil || record.ExecutionDigest != f.e.PlanDigest {
			t.Fatal("verified raw-review metadata", err)
		}
		qualifyRawQueryGrants(t, ctx, admin, poolFor, f.scenario, f.e, record.Version, *record.NativeBytes, func() error {
			return (auditapp.AuthorityPublisher{Ledger: f.scenario.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx)
		}, releasePermissionBurst)
	})

	t.Run("processing-restrictions-before-publication-and-prepaid-release", func(t *testing.T) {
		setupWithKeys(t, nil, func(f fixture, processing *processingTestFixture) {
			qualifyProcessingRestrictions(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, processing, func() error {
				_, err := f.publish(ctx)
				return err
			})
		})
	})

	t.Run("processing-restriction-fences-prepaid-native-output", func(t *testing.T) {
		setupWithKeys(t, nil, func(f fixture, processing *processingTestFixture) {
			if _, err := f.publish(ctx); err != nil {
				t.Fatal(err)
			}
			qualifyProcessingDownloadEffects(t, ctx, poolFor, store, keys, f.scenario, publishedContext{Expectation: f.e, Copies: f.copies, Catalog: artifact.CatalogFacts{NativeBytes: f.nativeBytes}}, f.reader, processing)
		})
	})

	t.Run("processing-discovery-compiled-role-and-bounded-pagination", func(t *testing.T) {
		s := create(t, 3)
		first, err := s.s.AdmitContext(ctx, s.a)
		if err != nil {
			t.Fatal("admit first discovery artifact", err)
		}
		next := s.a
		input := next.Plan.Input
		input.CaptureID = custodyID()
		next.Plan, err = planning.CompileContext(input, time.Now())
		if err != nil {
			t.Fatal("compile second discovery capture", err)
		}
		next.IdempotencyKey, next.OccurrenceID = custodyID(), custodyID()
		next.Registration.Location.ArtifactID, next.Registration.Location.AttemptID = custodyID(), custodyID()
		second, err := s.s.AdmitContext(ctx, next)
		if err != nil {
			t.Fatal("admit second discovery artifact", err)
		}
		prepareAdmitted(t, ctx, s, first, keys, keys, func(one fixture, processing *processingTestFixture) {
			two := prepareAdmitted(t, ctx, s, second, keys, keys, nil, false)
			publish := func(f fixture) {
				batch := s.batch
				batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
				batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
				if err := s.p.RefreshPermissions(ctx, batch); err != nil {
					t.Fatal("refresh discovery publication permissions", err)
				}
				if _, err := f.publish(ctx); err != nil {
					t.Fatal("publish discovery fixture", err)
				}
			}
			publish(one)
			qualifyProcessingDiscovery(t, ctx, admin, poolFor, s, processing, one.e, two.e, func() { publish(two) })
		}, true)
	})

	t.Run("ordinary-case-metadata-navigation-and-private-routing", func(t *testing.T) {
		f := setup(t)
		qualifyContextCase(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, func() error {
			_, err := f.publish(ctx)
			return err
		})
	})

	t.Run("evidence-share-recipient-read-revocation-expiry-and-deny", func(t *testing.T) {
		f := setupAdmitted(t, nil, nil, nil, true)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		publishAuthority := func() error {
			return (auditapp.AuthorityPublisher{Ledger: f.scenario.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx)
		}
		qualifyEvidenceShare(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, publishAuthority, store, keys)
	})

	t.Run("access-grant-approval-children-pool-revocation-and-expiry", func(t *testing.T) {
		f := setup(t)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		publishAuthority := func() error {
			return (auditapp.AuthorityPublisher{Ledger: f.scenario.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx)
		}
		qualifyAccessGrants(t, ctx, admin, poolFor, f.scenario, f.e, publishAuthority, releasePermissionBurst)
	})

	t.Run("capture-time-share-once-at-publication-and-owner-checked-at-admission", func(t *testing.T) {
		qualifyCaptureShare(t, ctx, admin, poolFor, create, func(t *testing.T, admit func(*testing.T, *captureAdmissionScenario) capture.Accepted) captureShareFixture {
			f := setupAdmitted(t, nil, nil, admit, true)
			return captureShareFixture{scenario: f.scenario, e: f.e, reader: f.reader, publish: func() (publishedContext, error) { return f.publish(ctx) },
				replay: func() error { _, err := f.publish(ctx); return err }}
		})
	})

	t.Run("policy-share-counter-limit-end-stop-and-revoke-all", func(t *testing.T) {
		qualifyPolicyShare(t, ctx, admin, poolFor, store, keys, create, func(t *testing.T, s captureAdmissionScenario, accepted capture.Accepted, initialize bool) captureShareFixture {
			f := prepareAdmitted(t, ctx, s, accepted, keys, keys, nil, initialize, true)
			return captureShareFixture{scenario: f.scenario, e: f.e, reader: f.reader, publish: func() (publishedContext, error) { return f.publish(ctx) }}
		}, func(t *testing.T, s *captureAdmissionScenario) shareCaptureAudit {
			qualified := newShareCaptureAudit(t, ctx, admin, poolFor, store, keys, *s)
			s.s = qualified.admissions
			shareCaptures[s.a.RootID] = qualified
			return qualified
		})
	})

	t.Run("policy-share-admitted-wide-sample-and-100-batch-cost", func(t *testing.T) {
		qualifyPolicyShare(t, ctx, admin, poolFor, store, keys, create, func(t *testing.T, s captureAdmissionScenario, accepted capture.Accepted, initialize bool) captureShareFixture {
			f := prepareAdmitted(t, ctx, s, accepted, keys, keys, nil, initialize, true)
			return captureShareFixture{scenario: f.scenario, e: f.e, reader: f.reader, publish: func() (publishedContext, error) { return f.publish(ctx) }}
		}, func(t *testing.T, s *captureAdmissionScenario) shareCaptureAudit {
			qualified := newShareCaptureAudit(t, ctx, admin, poolFor, store, keys, *s)
			s.s = qualified.admissions
			shareCaptures[s.a.RootID] = qualified
			return qualified
		}, true)
	})

	t.Run("progress-revisions-follow-publication", func(t *testing.T) {
		f := setup(t)
		pool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
		t.Cleanup(pool.Close)
		r, err := postgres.NewContextProgressReads(ctx, pool, f.scenario.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		var last int64
		check := func(phase, reason string, advanced bool) {
			t.Helper()
			got, err := r.ReadContextProgress(ctx, progressQuery(t, ctx, f.scenario))
			if err != nil || got.Phase != phase || got.ReasonCode != reason || (advanced && got.Revision <= last) || (!advanced && got.Revision != last) {
				t.Fatalf("progress %s/%s: %+v %v previous=%d", phase, reason, got, err, last)
			}
			last = got.Revision
		}
		check("Pending", "DispatchUnconfirmed", true)
		check("Pending", "DispatchUnconfirmed", false)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		check("Succeeded", "Published", true)
		if _, err := f.publish(ctx); err != nil {
			t.Fatal(err)
		}
		check("Succeeded", "Published", false)
	})

	t.Run("publication-concurrent-idempotent-and-readable", func(t *testing.T) {
		f := setup(t)
		var wg sync.WaitGroup
		out := make(chan publishedContext, 8)
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, e := f.publish(ctx)
				out <- r
				errs <- e
			}()
		}
		wg.Wait()
		close(out)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var published time.Time
		for r := range out {
			if published.IsZero() {
				published = r.PublishedAt
			}
			if !r.PublishedAt.Equal(published) || r.Copies != f.copies {
				t.Fatal("replay changed publication")
			}
		}
		retained, err := f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID)
		if err != nil || retained.DataClass != "metadata" || len(retained.Audience) != 2 || !retained.ExpiresAt.Equal(f.e.Registration.ExpiresAt) {
			t.Fatal("retained catalog provenance", err)
		}
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_catalog WHERE capture_id=$1", f.e.CaptureUID).Scan(&count); err != nil || count != 1 {
			t.Fatal("catalog duplicate", err)
		}
		if _, err = readerPool.Exec(ctx, "DELETE FROM context_catalog"); err == nil {
			t.Fatal("reader erased catalog")
		}
		// Current deletion state hides the artifact before any object deletion.
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET state='deleting' WHERE id=$1", f.e.Registration.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
			t.Fatal("deletion-pending artifact remained visible")
		}
		// Join the eight-way publication burst before the processing and native
		// download fixtures need the same bounded server connections.
		releasePermissionBurst()
		for _, pool := range []*pgxpool.Pool{readerPool} {
			pool.Reset()
		}
	})
	// Finished publication bursts must not retain all their idle connections
	// into another eight-way race. Keep the server budget and race size intact.
	releaseBurstConnections := func() {
		// The shared permission reader belongs to the outer fixture. Its
		// completed publication burst has joined before this boundary too.
		// Release those idle connections through that owner; keep the server
		// budget, per-pool ceiling and later eight-way race unchanged.
		releasePermissionBurst()
		for _, pool := range []*pgxpool.Pool{readerPool} {
			pool.Reset()
		}
	}
	releaseBurstConnections()
	qualifyDownloadSessions(t, ctx, admin, poolFor, store, keys, func(t *testing.T, provider func(string) (evidence.KeySealer, evidence.KeyOpener)) (captureAdmissionScenario, publishedContext) {
		f := setupWithKeys(t, provider, nil)
		call := ctx
		if f.scenario.nativeSources != nil {
			call = f.scenario.nativeSources.ctx
		}
		published, err := f.publish(call)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, published
	}, releaseBurstConnections)
	releaseBurstConnections()
	qualifyDownloadControl(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, publishedContext) {
		f := setup(t)
		p, err := f.publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyDownloadResponses(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, publishedContext) {
		f := setup(t)
		p, err := f.publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyDownloadStop(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, publishedContext) {
		f := setup(t)
		p, err := f.publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	// Construction with a SELECT role cannot silently obtain mutation authority.
	if _, err := postgres.NewContextPublications(ctx, readerPool, "invalid"); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("invalid publication root")
	}
}
func minPublicationTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
