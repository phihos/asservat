package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"testing"
	"time"
)

type contextPublicationTestGate struct {
	check func(context.Context, artifact.ContextExpectation) (artifact.PublicationAuthority, error)
}

func (g contextPublicationTestGate) CheckContextPublication(ctx context.Context, e artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
	return g.check(ctx, e)
}

// Real SQL/S3/Tink, separate SQL roles and full native verification. This fixture
// deliberately synthesizes collector/result/retention authority, not production
// enrollment or permission to enable the public capture workflow.
func qualifyContextPublications(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario, releasePermissionBurst func()) {
	t.Helper()
	verifierPool := poolFor("context_verify_runtime", "synthetic-context-verify")
	auditPool := poolFor("context_verification_audit_runtime", "synthetic-context-audit")
	publishPool := poolFor("context_publish_runtime", "synthetic-context-publish")
	readerPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
	intentPool := poolFor("capture_audit_runtime", "synthetic-capture-audit")
	defer verifierPool.Close()
	defer auditPool.Close()
	defer publishPool.Close()
	defer readerPool.Close()
	defer intentPool.Close()
	for _, role := range []struct {
		pool  *pgxpool.Pool
		query string
	}{
		{verifierPool, "INSERT INTO context_catalog(artifact_id,capture_id,root_id) SELECT id,id,root_id FROM context_capture LIMIT 0"},
		{verifierPool, "UPDATE context_verification SET audit_acknowledged_at=clock_timestamp()"},
		{publishPool, "UPDATE context_verification SET authority_digest=authority_digest"},
		{publishPool, "UPDATE custody_attempt SET expires_at=expires_at"},
		{auditPool, "UPDATE context_verification SET expectation_digest=expectation_digest"},
		{readerPool, "UPDATE context_catalog SET published_at=clock_timestamp()"},
	} {
		if _, err := role.pool.Exec(ctx, role.query); err == nil {
			t.Fatal("publication facet has excess SQL privilege")
		}
	}
	type fixture struct {
		scenario                       captureAdmissionScenario
		e                              artifact.ContextExpectation
		copies                         artifact.Copies
		verify, audit, publish, reader *postgres.ContextPublications
		publisher                      evidence.ContextPublisher
		gate                           contextPublicationTestGate
	}
	var prepareAdmitted func(t *testing.T, ctx context.Context, s captureAdmissionScenario, accepted capture.Accepted, seal evidence.KeySealer, open evidence.KeyOpener, processingCheck func(fixture, *processingTestFixture), initialize bool) fixture
	// admit, when set, replaces the direct admission (ADR-235 admits a
	// reviewed preview carrying a sharing instruction).
	setupAdmitted := func(t *testing.T, provider func(string) (evidence.KeySealer, evidence.KeyOpener), processingCheck func(fixture, *processingTestFixture), admit func(*testing.T, *captureAdmissionScenario) capture.Accepted) fixture {
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
		var accepted capture.Accepted
		var err error
		if admit != nil {
			accepted = admit(t, &s)
		} else if accepted, err = s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		return prepareAdmitted(t, ctx, s, accepted, seal, open, processingCheck, true)
	}
	// prepareAdmitted stores, verifies and audits one admitted capture of s so
	// that it is ready to publish. A scenario's processing root is accepted and
	// initialized once (initialize), by its first prepared capture; later
	// captures of the same root are covered by it.
	prepareAdmitted = func(t *testing.T, ctx context.Context, s captureAdmissionScenario, accepted capture.Accepted, seal evidence.KeySealer, open evidence.KeyOpener, processingCheck func(fixture, *processingTestFixture), initialize bool) fixture {
		t.Helper()
		var err error
		var f fixture
		f.scenario = s
		f.e = accepted.Expectation
		var processing *processingTestFixture
		if initialize {
			processing = newProcessingTestFixture(t, ctx, poolFor, store, keys, s, f.e)
			defer processing.Close()
			initializeProcessingTestFixtureWith(t, ctx, processing)
		}
		for _, pair := range []struct {
			pool *pgxpool.Pool
			dst  **postgres.ContextPublications
		}{{verifierPool, &f.verify}, {auditPool, &f.audit}, {publishPool, &f.publish}, {readerPool, &f.reader}} {
			*pair.dst, err = postgres.NewContextPublications(ctx, pair.pool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
			if err != nil {
				t.Fatal(err)
			}
		}
		// A later capture of the root may already be audited: the first
		// preparation's publisher writes every pending capture intent.
		if _, err = f.verify.AcceptedContextForPublication(ctx, accepted.CaptureID); err == nil && initialize {
			t.Fatal("unaudited capture accepted for publication")
		}
		if _, err = f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
			t.Fatal("reservation became evidence")
		}
		intents, err := postgres.NewCaptureIntentAudits(ctx, intentPool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
			t.Fatal(err)
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
		f.copies, err = prepared.StoreContext(ctx, native, at, at)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := objectstore.NewContextVerifier(bound, open)
		if err != nil {
			t.Fatal(err)
		}
		f.gate = contextPublicationTestGate{check: func(ctx context.Context, e artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
			projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
			if err != nil {
				return artifact.PublicationAuthority{}, publicationStepError("permission gate", err)
			}
			policies, err := nativeFixturePublicationPolicies(ctx, s)
			if err != nil {
				return artifact.PublicationAuthority{}, publicationStepError("retention gate", err)
			}
			recovery, err := s.recovery.reader.RecoveryState(ctx)
			if err != nil {
				return artifact.PublicationAuthority{}, publicationStepError("recovery gate", err)
			}
			now := time.Now().UTC()
			return artifact.PublicationAuthority{Recovery: recovery, Retention: policies.Proof, RootID: s.a.RootID, CaptureID: e.CaptureUID, PermissionEpoch: projection.Revision.UID, PermissionSequence: projection.Revision.Generation, ProjectionDigest: artifact.Digest(projection.Revision.Digest), ExpectationDigest: evidence.ContextExpectationDigest(e), AuthorityDigest: artifact.Digest{99}, CheckedAt: now, ValidUntil: minPublicationTime(minPublicationTime(policies.Proof.ValidUntil, projection.FreshUntil), recovery.FreshUntil)}, nil
		}}
		f.publisher = evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: f.verify, ContextVerificationRecorder: f.verify, ContextVerificationAuditor: f.audit, ContextCatalogPublisher: f.publish}, Authority: f.gate, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: store, Seal: keys, Open: keys}, Now: time.Now}
		f.publisher.Ledger = publicationDiagnosticLedger{f.publisher.Ledger}
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

	qualifyPermissionPublicationAuditHistory(t, ctx, admin, func(t *testing.T) permissionPublicationAuditFixture {
		f := setup(t)
		return permissionPublicationAuditFixture{expectation: f.e, copies: f.copies, verify: f.verify, audit: f.audit, publish: f.publish, gate: f.gate, publisher: f.publisher}
	})

	// Each version case starts with a new genuine published fixture and keeps the
	// original short authority throughout corruption, denial and exact restore.
	for _, kind := range []string{"capture", "verification"} {
		for _, version := range []string{"", "null"} {
			label := version
			if label == "" {
				label = "empty"
			}
			t.Run("publication-audit-history-"+kind+"-"+label, func(t *testing.T) {
				f := setup(t)
				if _, err := f.reader.ContextProjectionEvidence(ctx, f.e.Registration.Location.ArtifactID); err == nil {
					t.Fatal("unpublished custody became an approved projection source")
				}
				original, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
				if err != nil {
					t.Fatal("original published fixture", err)
				}
				authority, err := f.gate.CheckContextPublication(ctx, f.e)
				if err != nil {
					t.Fatal("original publication authority", err)
				}
				positive := func() {
					t.Helper()
					if _, err := f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err != nil {
						t.Fatal("positive audience", err)
					}
					if _, err := f.reader.ContextDownloadEvidence(ctx, f.e.Registration.Location.ArtifactID); err != nil {
						t.Fatal("positive download catalog", err)
					}
					projection, err := f.reader.ContextProjectionEvidence(ctx, f.e.Registration.Location.ArtifactID)
					if err != nil || projection.CaseID != f.e.CaseID || projection.CaptureID != f.e.CaptureUID || projection.Version != evidence.ContextCopiesDigest(f.copies) ||
						projection.SourceFormat != artifact.ContextFormat || projection.SourceProjectionDigest != analysis.ContextSourceProjectionDigest() || projection.DataClass != "metadata" ||
						projection.Retained.Registration.Location != f.e.Registration.Location || !projection.Retained.Effective.ExpiresAt.Equal(f.e.Registration.ExpiresAt) ||
						!projection.ValidUntil.After(projection.ObservedAt) || projection.ValidUntil.After(projection.ObservedAt.Add(identity.EvidenceReadRequestWindow)) {
						t.Fatal("approved projection lost protected source identity or original bounds", err)
					}
					replay, err := f.publish.PublishContext(ctx, f.e, f.copies, authority)
					if err != nil || !replay.PublishedAt.Equal(original.PublishedAt) {
						t.Fatal("positive original publication replay", err)
					}
				}
				positive()
				withPublicationAuditVersion(t, ctx, admin, kind, f.e.CaptureUID, version, func() {
					if kind == "capture" {
						if _, err := f.verify.AcceptedContextForPublication(ctx, f.e.CaptureUID); err == nil {
							t.Fatal("historical capture receipt became current acceptance")
						}
					}
					if _, err := f.publish.PublishContext(ctx, f.e, f.copies, authority); err == nil {
						t.Fatal("historical audit authorized publication replay")
					}
					if _, err := f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
						t.Fatal("historical audit became current audience")
					}
					if _, err := f.reader.ContextDownloadEvidence(ctx, f.e.Registration.Location.ArtifactID); err == nil {
						t.Fatal("historical audit became download catalog authority")
					}
					if _, err := f.reader.ContextProjectionEvidence(ctx, f.e.Registration.Location.ArtifactID); err == nil {
						t.Fatal("historical audit became approved projection source authority")
					}
					if !authority.Valid(f.e, evidence.ContextExpectationDigest(f.e), time.Now()) {
						t.Fatal("receipt denial crossed original authority deadline")
					}
				})
				positive()
			})
		}
	}

	t.Run("processing-restrictions-before-publication-and-prepaid-release", func(t *testing.T) {
		setupWithKeys(t, nil, func(f fixture, processing *processingTestFixture) {
			qualifyProcessingRestrictions(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, processing, func() error {
				_, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
				return err
			})
		})
	})

	t.Run("processing-restriction-fences-prepaid-native-output", func(t *testing.T) {
		setupWithKeys(t, nil, func(f fixture, processing *processingTestFixture) {
			if _, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies); err != nil {
				t.Fatal(err)
			}
			qualifyProcessingDownloadEffects(t, ctx, poolFor, store, keys, f.scenario, artifact.PublishedContext{Expectation: f.e, Copies: f.copies}, f.reader, processing)
		})
	})

	t.Run("ordinary-case-metadata-navigation-and-private-routing", func(t *testing.T) {
		f := setup(t)
		qualifyContextCase(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, func() error {
			_, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
			return err
		})
	})

	t.Run("evidence-share-recipient-read-revocation-expiry-and-deny", func(t *testing.T) {
		f := setup(t)
		if _, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies); err != nil {
			t.Fatal(err)
		}
		publishAuthority := func() error {
			return (auditapp.AuthorityPublisher{Ledger: f.scenario.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx)
		}
		qualifyEvidenceShare(t, ctx, admin, poolFor, f.scenario, f.e, f.reader, publishAuthority)
	})

	t.Run("capture-time-share-once-at-publication-and-owner-checked-at-admission", func(t *testing.T) {
		qualifyCaptureShare(t, ctx, admin, poolFor, create, func(t *testing.T, admit func(*testing.T, *captureAdmissionScenario) capture.Accepted) captureShareFixture {
			f := setupAdmitted(t, nil, nil, admit)
			return captureShareFixture{scenario: f.scenario, e: f.e, reader: f.reader, publish: func() (artifact.PublishedContext, error) { return f.publisher.Publish(ctx, f.e.CaptureUID, f.copies) },
				replay: func() error {
					a, err := f.gate.CheckContextPublication(ctx, f.e)
					if err == nil {
						_, err = f.publish.PublishContext(ctx, f.e, f.copies, a)
					}
					return err
				}}
		})
	})

	t.Run("policy-share-counter-limit-end-stop-and-revoke-all", func(t *testing.T) {
		qualifyPolicyShare(t, ctx, admin, poolFor, store, keys, create, func(t *testing.T, s captureAdmissionScenario, accepted capture.Accepted, initialize bool) captureShareFixture {
			f := prepareAdmitted(t, ctx, s, accepted, keys, keys, nil, initialize)
			return captureShareFixture{scenario: f.scenario, e: f.e, reader: f.reader, publish: func() (artifact.PublishedContext, error) { return f.publisher.Publish(ctx, f.e.CaptureUID, f.copies) }}
		})
	})

	t.Run("progress-revisions-follow-durable-verification-audit-and-publication", func(t *testing.T) {
		f := setup(t)
		pool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
		t.Cleanup(pool.Close)
		r, err := postgres.NewContextProgressReads(ctx, pool, f.scenario.a.RootID, f.scenario.recovery.guard)
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
		a, err := f.gate.CheckContextPublication(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		record, err := f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
		if err != nil {
			t.Fatal(err)
		}
		check("Finalizing", "VerificationAuditPending", true)
		if _, err = f.verify.RecordContextVerification(ctx, f.e, f.copies, a); err != nil {
			t.Fatal(err)
		}
		check("Finalizing", "VerificationAuditPending", false)
		receipt, err := f.publisher.Audit.WriteContextVerification(ctx, record)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
			t.Fatal(err)
		}
		check("Finalizing", "PublicationPending", true)
		if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
			t.Fatal(err)
		}
		check("Finalizing", "PublicationPending", false)
		if _, err = f.publish.PublishContext(ctx, f.e, f.copies, a); err != nil {
			t.Fatal(err)
		}
		check("Succeeded", "Published", true)
		if _, err = f.publish.PublishContext(ctx, f.e, f.copies, a); err != nil {
			t.Fatal(err)
		}
		check("Succeeded", "Published", false)
	})

	for _, phase := range []string{"verification", "publication"} {
		t.Run("recovery-blocks-"+phase, func(t *testing.T) {
			f := setup(t)
			a, err := f.gate.CheckContextPublication(ctx, f.e)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "publication" {
				record, err := f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := f.publisher.Audit.WriteContextVerification(ctx, record)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", f.scenario.recovery.installation); err != nil {
				t.Fatal(err)
			}
			if phase == "verification" {
				_, err = f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
			} else {
				_, err = f.publish.PublishContext(ctx, f.e, f.copies, a)
			}
			if err == nil {
				t.Fatal("blocked recovery authorized effect")
			}
			var count int
			if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_catalog WHERE capture_id=$1", f.e.CaptureUID).Scan(&count); err != nil || count != 0 {
				t.Fatal("unauthorized publication", count, err)
			}
		})
	}
	for _, phase := range []string{"verification", "publication"} {
		t.Run("retention-source-fences-"+phase, func(t *testing.T) {
			f := setup(t)
			a, err := f.gate.CheckContextPublication(ctx, f.e)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "publication" {
				record, err := f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := f.publisher.Audit.WriteContextVerification(ctx, record)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.scenario.retention.sources.SuspendRetention(ctx, f.scenario.retention.fence); err != nil {
				t.Fatal(err)
			}
			if phase == "verification" {
				_, err = f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
			} else {
				_, err = f.publish.PublishContext(ctx, f.e, f.copies, a)
			}
			if err == nil {
				t.Fatal("stale retention authorized effect")
			}
			var count int
			if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_catalog WHERE capture_id=$1", f.e.CaptureUID).Scan(&count); err != nil || count != 0 {
				t.Fatal("unauthorized publication", count, err)
			}
		})
	}

	t.Run("verified-publication-concurrent-idempotent-and-readable", func(t *testing.T) {
		f := setup(t)
		var wg sync.WaitGroup
		out := make(chan artifact.PublishedContext, 8)
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, e := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
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
	})
	t.Run("verification-audit-failure-stays-invisible", func(t *testing.T) {
		f := setup(t)
		f.publisher.Audit = &objectstore.ContextVerificationObjects{Store: store, Open: keys}
		if _, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies); err == nil {
			t.Fatal("failed audit published")
		}
		if _, err := f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
			t.Fatal("verified without audit became visible")
		}
		var before time.Time
		if err := admin.QueryRow(ctx, "SELECT verified_at FROM context_verification WHERE capture_id=$1", f.e.CaptureUID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		f.publisher.Audit = &objectstore.ContextVerificationObjects{Store: store, Seal: keys, Open: keys}
		r, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil || !r.VerifiedAt.Equal(before) {
			t.Fatal("retry renewed verification", err)
		}
	})
	t.Run("generic-custody-cannot-publish", func(t *testing.T) {
		f := setup(t)
		genericPool := poolFor("custody_runtime", "synthetic-runtime")
		defer genericPool.Close()
		generic, err := postgres.New(ctx, genericPool)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := store.ForCustody(f.e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		if err = (evidence.Custodian{Ledger: generic, Verifier: bound}).VerifyAndStore(ctx, f.e.Registration, f.copies); err != nil {
			t.Fatal(err)
		}
		a, err := f.gate.CheckContextPublication(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.publish.PublishContext(ctx, f.e, f.copies, a); err == nil {
			t.Fatal("unverified copies published")
		}
		bad := f.copies
		bad[0].SHA256[0]++
		if _, err = f.publisher.Publish(ctx, f.e.CaptureUID, bad); err == nil {
			t.Fatal("bad bytes published")
		}
		var n int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_verification WHERE capture_id=$1", f.e.CaptureUID).Scan(&n); err != nil || n != 0 {
			t.Fatal("failed verifier wrote proof", err)
		}
	})
	t.Run("publication-rechecks-locked-authority-and-expiry", func(t *testing.T) {
		f := setup(t)
		a, err := f.gate.CheckContextPublication(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		record, err := f.verify.RecordContextVerification(ctx, f.e, f.copies, a)
		if err != nil {
			t.Fatal(err)
		}
		objects := &objectstore.ContextVerificationObjects{Store: store, Seal: keys, Open: keys}
		receipt, err := objects.WriteContextVerification(ctx, record)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
			t.Fatal(err)
		}
		bad := receipt
		bad.SHA256[0]++
		if err = f.audit.AcknowledgeContextVerification(ctx, record, bad); err == nil {
			t.Fatal("audit receipt replaced")
		}
		if _, err = admin.Exec(ctx, "UPDATE context_verification SET authority_digest=decode(repeat('01',32),'hex') WHERE capture_id=$1", f.e.CaptureUID); err == nil {
			t.Fatal("immutable verification replaced")
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM custody_allocation WHERE id=$1 FOR UPDATE", f.e.Registration.AllocationID); err != nil {
			t.Fatal(err)
		}
		a.CheckedAt = time.Now().UTC()
		a.ValidUntil = a.CheckedAt.Add(100 * time.Millisecond)
		done := make(chan error, 1)
		go func() { _, err := f.publish.PublishContext(ctx, f.e, f.copies, a); done <- err }()
		time.Sleep(200 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("expired lock waiter published")
		}
		a, err = f.gate.CheckContextPublication(ctx, f.e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, "UPDATE permission_stream SET suspended=true WHERE id=$1", f.scenario.a.RootID); err != nil {
			t.Fatal(err)
		}
		if _, err = f.publish.PublishContext(ctx, f.e, f.copies, a); err == nil {
			t.Fatal("revoked root published")
		}
		if _, err = f.reader.RetainedAudience(ctx, f.e.Registration.Location.ArtifactID); err == nil {
			t.Fatal("failed publication became readable")
		}
		// Exact historical audit remains idempotent after revocation.
		if err = f.audit.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
			t.Fatal(err)
		}
		var charged int64
		if err = admin.QueryRow(ctx, "SELECT charged_bytes FROM custody_allocation WHERE id=$1", f.e.Registration.AllocationID).Scan(&charged); err != nil || charged != f.e.Registration.ReservedBytes() {
			t.Fatal("failed publication refunded custody", err)
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
		for _, pool := range []*pgxpool.Pool{verifierPool, auditPool, publishPool, readerPool, intentPool} {
			pool.Reset()
		}
	}
	releaseBurstConnections()
	qualifyDownloadSessions(t, ctx, admin, poolFor, store, keys, func(t *testing.T, provider func(string) (evidence.KeySealer, evidence.KeyOpener)) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setupWithKeys(t, provider, nil)
		call := ctx
		if f.scenario.nativeSources != nil {
			call = f.scenario.nativeSources.ctx
		}
		published, err := f.publisher.Publish(call, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, published
	})
	releaseBurstConnections()
	qualifyDownloadControl(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setup(t)
		p, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyDownloadResponses(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setup(t)
		p, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyDownloadStop(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setup(t)
		p, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyDownloadStopLifecycle(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setup(t)
		p, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyRetentionLifecycle(t, ctx, admin, poolFor, store, keys, func(t *testing.T) (captureAdmissionScenario, artifact.PublishedContext) {
		f := setup(t)
		p, err := f.publisher.Publish(ctx, f.e.CaptureUID, f.copies)
		if err != nil {
			t.Fatal(err)
		}
		return f.scenario, p
	})
	releaseBurstConnections()
	qualifyRetentionSources(t, ctx, admin, poolFor, store, keys)
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
