package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Baseline business-ledger measurements, not a qualified capacity profile.
// The owned fixture really admits, encrypts, verifies and publishes the artifact;
// the share mutations use the installation's compiled hub role/current adapter.
// Synthetic human/permission inputs and local test crypto remain explicit.
// Public-operation audit and remote provider costs are outside these samples.
func TestShareMetadataRetirementBaselineWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
			// Accept the full owner set BEFORE admission/publication. Never widen
			// the immutable audience of an existing artifact for measurement.
			next := f.batch
			next.Bases = slices.Clone(next.Bases)
			for n := 0; n < authorization.ShareMaxManagers; n++ {
				base := next.Bases[0]
				base.Resource.UID = custodyID()
				base.Resource.SpecDigest = sha256.Sum256([]byte(fmt.Sprintf("synthetic-share-owner-%d", n)))
				base.Roles = []string{"evidence-owner"}
				base.ScopeDigest = configapp.PermissionScopeDigest(base)
				next.Bases = append(next.Bases, base)
			}
			next.RequestID, next.InputDigest, next.Initial = custodyID(), artifact.Digest{83}, nil
			next.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
			next.FreshUntil = next.ObservedAt.Add(5 * time.Second)
			accepted, err := f.permission.AcceptPermissions(ctx, next)
			if err != nil {
				t.Fatal("accept original eight-owner audience", err)
			}
			next.ExpectedSequence = accepted.Sequence
			f.batch = next
			for range 2 {
				if err = (auditapp.AuthorityPublisher{Ledger: f.permission, Objects: f.authority}).PublishAuthority(ctx); err != nil {
					t.Fatal("audit original eight-owner audience", err)
				}
			}
		})
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("initialize original capacity", err)
		}
		f.open(t)
		o := f.rootObservation(t)
		root, err := f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("reserve original root", err)
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("back original root", err)
		}
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
		if err != nil || !root.AdmissionReady(time.Now()) {
			t.Fatal("publish original root", err)
		}
		coordinator := capacityapp.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
		enrolled, err := coordinator.Reconcile(ctx, f.workloadObservation(t, 0))
		if err != nil {
			t.Fatal("original workload enrollment", err)
		}
		originalPool := f.fixturePool
		var processingPools []*pgxpool.Pool
		f.fixturePool = func(role, password string) *pgxpool.Pool {
			pool := originalPool(role, password)
			processingPools = append(processingPools, pool)
			return pool
		}
		f.initializeManagedProcessing(t, root)
		f.fixturePool = originalPool
		for _, pool := range processingPools {
			pool.Close()
		}
		s, published := publishQueryLedgerContext(t, f, root, enrolled, false)
		qualifyShareMetadataBaseline(t, f, s, published)
	})
}

type shareMetadataSample struct {
	WAL                                           string
	Rows, Active, TupleBytes, MaxTupleBytes       int64
	HeapBytes, IndexBytes, ToastBytes, TotalBytes int64
}

func sampleShareMetadata(t *testing.T, f *capacitySQLFixture, artifactID string) shareMetadataSample {
	t.Helper()
	var s shareMetadataSample
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_current_wal_insert_lsn()::text,
 count(*)::bigint,count(*) FILTER(WHERE revoked_at IS NULL AND expires_at>clock_timestamp())::bigint,
 coalesce(sum(pg_column_size(r)),0)::bigint,coalesce(max(pg_column_size(r)),0)::bigint,
 pg_relation_size('public.evidence_share'),pg_indexes_size('public.evidence_share'),
 (SELECT pg_total_relation_size(reltoastrelid) FROM pg_class WHERE oid='public.evidence_share'::regclass),
 pg_total_relation_size('public.evidence_share')
 FROM evidence_share r WHERE root_id=$1 AND artifact_id=$2`, f.input.PermissionRootID, artifactID).Scan(&s.WAL, &s.Rows, &s.Active, &s.TupleBytes, &s.MaxTupleBytes, &s.HeapBytes, &s.IndexBytes, &s.ToastBytes, &s.TotalBytes); err != nil {
		t.Fatal("share metadata sample", err)
	}
	return s
}

func logShareMetadata(t *testing.T, f *capacitySQLFixture, phase string, before, after shareMetadataSample, elapsed time.Duration) {
	t.Helper()
	var wal int64
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, after.WAL, before.WAL).Scan(&wal); err != nil || wal < 0 {
		t.Fatal("share WAL observation", err, wal)
	}
	t.Logf("UNQUALIFIED share_business phase=%s elapsed_ms=%d rows=%d active=%d row_delta=%d tuple_bytes=%d max_tuple_bytes=%d heap_bytes=%d indexes_bytes=%d toast_bytes=%d total_bytes=%d heap_growth=%d indexes_growth=%d toast_growth=%d total_growth=%d whole_instance_wal_delta=%d; logical counts are exact-artifact; physical sizes cover entire relations; WAL includes background noise, aborted work and page images; excludes public audit/provider work", phase, elapsed.Milliseconds(), after.Rows, after.Active, after.Rows-before.Rows, after.TupleBytes, after.MaxTupleBytes, after.HeapBytes, after.IndexBytes, after.ToastBytes, after.TotalBytes, after.HeapBytes-before.HeapBytes, after.IndexBytes-before.IndexBytes, after.ToastBytes-before.ToastBytes, after.TotalBytes-before.TotalBytes, wal)
}

func qualifyShareMetadataBaseline(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, published artifact.PublishedContext) {
	t.Helper()
	ctx, hub, e := f.ctx, f.roles["hub-runtime"], published.Expectation
	store, err := postgres.NewEvidenceShares(ctx, hub, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal("compiled hub share store", err)
	}
	catalog, err := postgres.NewContextPublications(ctx, hub, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal("published share source", err)
	}
	verified, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil {
		t.Fatal("independently verified source", err)
	}
	var managers []artifact.AudienceAssignment
	for _, a := range e.Audience {
		if a.Role == "evidence-owner" {
			managers = append(managers, a)
		}
	}
	if len(managers) != authorization.ShareMaxManagers {
		t.Fatal("original capture does not retain eight owners", len(managers))
	}
	creator := s.a.Eligibility.VerifiedIdentity.Principal
	recipients := make([]authorization.ShareRecipient, authorization.ShareMaxRecipients)
	for n := range recipients {
		var entropy [192]byte // 256 printable bytes, the legal recipient-ID maximum.
		if _, err = rand.Read(entropy[:]); err != nil {
			t.Fatal(err)
		}
		recipients[n] = authorization.ShareRecipient{Kind: "Group", Issuer: creator.Issuer, ID: base64.RawURLEncoding.EncodeToString(entropy[:])}
	}
	slices.SortFunc(recipients, func(a, b authorization.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	t.Logf("representative count-maximal share: managers=%d recipients=%d recipient_id_bytes=%d issuer_bytes=%d; actual original owner field widths; not maximum-byte issuer/manager qualification; no policy100 measurement (existing acceptance/publication fixture is not a reusable constructor)", len(managers), len(recipients), len(recipients[0].ID), len(creator.Issuer))
	proof := func() artifact.RecoveryProof {
		t.Helper()
		f.refreshFleet(t)
		p, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal("original current recovery", err)
		}
		return p
	}
	create := func(n int) (sharing.Request, authorization.Share) {
		t.Helper()
		r := sharing.Request{Share: authorization.Share{ID: custodyID(), RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaseID: e.CaseID, Target: s.a.Eligibility.Target, Version: verified.Version, Creator: creator, Management: slices.Clone(managers), Recipients: slices.Clone(recipients), ExpiresAt: e.Registration.ExpiresAt}, IdempotencyKey: fmt.Sprintf("synthetic-history-%03d", n), RequestDigest: sha256.Sum256([]byte(fmt.Sprintf("synthetic-history-%03d", n)))}
		out, replay, err := store.CreateShare(ctx, r, proof())
		if err != nil || replay || len(out.Management) != 8 || len(out.Recipients) != 8 {
			t.Fatal("create original share", n, err, replay)
		}
		return r, out
	}
	baseline := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	wholeStarted := time.Now()
	started := wholeStarted
	request, first := create(0)
	firstSample := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	logShareMetadata(t, f, "create-eight-by-eight", baseline, firstSample, time.Since(started))
	p := proof()
	before := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	started = time.Now()
	if replayed, replay, err := store.CreateShare(ctx, request, p); err != nil || !replay || replayed.ID != first.ID {
		t.Fatal("create replay", err, replay)
	}
	logShareMetadata(t, f, "create-replay", before, sampleShareMetadata(t, f, e.Registration.Location.ArtifactID), time.Since(started))

	// A real management transfer rewrites the same count-maximal owner set.
	replacement := slices.Clone(managers)
	slices.Reverse(replacement)
	managerIDs := make([]string, len(managers))
	for n, m := range managers {
		managerIDs[n] = m.AssignmentID
	}
	transfer := sharing.Transfer{ShareID: first.ID, Actor: creator, Managers: managerIDs, Management: replacement, ExpectedRevision: first.Revision, IdempotencyKey: "synthetic-transfer", RequestDigest: artifact.Digest{84}}
	p = proof()
	before = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	started = time.Now()
	first, replay, err := store.TransferShare(ctx, transfer, p)
	if err != nil || replay || first.Revision != 2 {
		t.Fatal("full management transfer", err, replay)
	}
	logShareMetadata(t, f, "transfer-eight-managers", before, sampleShareMetadata(t, f, e.Registration.Location.ArtifactID), time.Since(started))
	all := []authorization.Share{first}
	for n := 1; n < authorization.ShareMaxActivePerArtifact; n++ {
		_, share := create(n)
		all = append(all, share)
	}
	full := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	if full.Rows != 32 || full.Active != 32 {
		t.Fatal("actual active cap setup", full)
	}
	refused := request
	refused.Share.ID, refused.IdempotencyKey, refused.RequestDigest = custodyID(), "synthetic-capacity-refusal", artifact.Digest{85}
	p = proof()
	before = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	started = time.Now()
	if _, replay, err := store.CreateShare(ctx, refused, p); !errors.Is(err, capture.ErrCapacity) || replay {
		t.Fatal("thirty-third active share was not refused", err, replay)
	}
	after := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	if after.Rows != 32 || after.Active != 32 {
		t.Fatal("capacity refusal changed history", after)
	}
	logShareMetadata(t, f, "active-cap-refusal-rollback", before, after, time.Since(started))

	for _, share := range all {
		p = proof()
		before = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
		started = time.Now()
		out, replay, err := store.RevokeShare(ctx, sharing.Revocation{ShareID: share.ID, Actor: creator, ExpectedRevision: share.Revision, IdempotencyKey: "synthetic-revoke-" + share.ID}, p)
		if err != nil || replay || out.RevokedAt.IsZero() || out.Revision != share.Revision+1 {
			t.Fatal("revoke original share", err, replay)
		}
		if share.ID == first.ID {
			logShareMetadata(t, f, "revoke-after-transfer", before, sampleShareMetadata(t, f, e.Registration.Location.ArtifactID), time.Since(started))
		}
	}
	for n := 32; n < 64; n++ {
		_, share := create(n)
		all = append(all, share)
	}
	after = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	if after.Rows != 64 || after.Active != 32 {
		t.Fatal("active cap unexpectedly bounded retained history", after)
	}

	// Execute the actual generated mutation under the compiled hub role and
	// roll it back explicitly. This observes aborted tuple/index/WAL costs;
	// it does not claim the adapter's outer recovery transaction was exercised.
	last := all[len(all)-1]
	var shareID, rootID pgtype.UUID
	_ = shareID.Scan(last.ID)
	_ = rootID.Scan(s.a.RootID)
	before = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	started = time.Now()
	tx, err := hub.Begin(ctx)
	if err != nil {
		t.Fatal("begin generated mutation rollback", err)
	}
	defer tx.Rollback(context.Background())
	q := custodydb.New(tx)
	if _, err = q.ReadShareForUpdate(ctx, custodydb.ReadShareForUpdateParams{RootID: rootID, ID: shareID}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.RevokeShare(ctx, custodydb.RevokeShareParams{RootID: rootID, ID: shareID, RevokeKey: pgtype.Text{String: "synthetic-explicit-rollback", Valid: true}}); err != nil {
		t.Fatal("generated full revoke before rollback", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal("rollback generated mutation", err)
	}
	got, err := store.Share(ctx, last.ID)
	if err != nil || !got.RevokedAt.IsZero() || got.Revision != last.Revision {
		t.Fatal("rollback retained a mutation", err)
	}
	logShareMetadata(t, f, "generated-full-revoke-explicit-rollback", before, sampleShareMetadata(t, f, e.Registration.Location.ArtifactID), time.Since(started))
	if _, replay, err = store.RevokeShare(ctx, sharing.Revocation{ShareID: last.ID, Actor: creator, ExpectedRevision: last.Revision, IdempotencyKey: "synthetic-final-revoke"}, proof()); err != nil || replay {
		t.Fatal("free one active position", err)
	}
	create(64)
	after = sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	if after.Rows != 65 || after.Active != 32 {
		t.Fatal("repeat cycle did not retain history beyond active cap", after)
	}
	logShareMetadata(t, f, "complete-65-row-retained-history", baseline, after, time.Since(wholeStarted))
	if _, err = hub.Exec(ctx, `DELETE FROM evidence_share WHERE root_id=$1`, s.a.RootID); err == nil {
		t.Fatal("compiled hub can physically delete share history")
	}
}
