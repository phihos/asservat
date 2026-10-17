package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	capacityvalue "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type capacityManagedSession struct {
	session  artifact.DownloadSession
	original string
}

func (f *capacitySQLFixture) managedDownloadSession(t *testing.T, root app.RootConfiguration, enrollment app.Enrollment) capacityManagedSession {
	t.Helper()
	f.initializeManagedProcessing(t, root)
	// Read-only fixture role deliberately has no private validation-function
	// EXECUTE grants. The product queries must work with ordinary table reads.
	if _, err := f.admin.Exec(f.ctx, `CREATE ROLE capacity_session_projection_fixture LOGIN NOINHERIT PASSWORD 'synthetic-session-projection';
GRANT CONNECT ON DATABASE custody_test TO capacity_session_projection_fixture;
GRANT USAGE ON SCHEMA public TO capacity_session_projection_fixture;
GRANT SELECT ON artifact_download,download_control_allocation,download_native_backing TO capacity_session_projection_fixture;`); err != nil {
		t.Fatal(err)
	}

	s, accepted := f.admitManagedContext(t, root, enrollment)
	e := accepted.Expectation
	f.checkManagedProcessingLineage(t, e)
	bound, err := f.store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewContextProducer(bound, f.keys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.PrepareContext(f.ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	at := time.Now().UTC()
	payload, err := json.Marshal(map[string]any{"format": artifact.ContextFormat, "namespaceUID": e.NamespaceUID, "podUID": e.PodUID, "resourceVersion": "synthetic-1", "observedAt": at, "phase": "Running", "ready": "True", "initialized": "True", "scheduled": "True", "runtimeInstances": 1, "running": 1, "waiting": 0, "terminated": 0, "restarts": 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	copies, err := prepared.StoreContext(f.ctx, payload, at, at)
	if err != nil {
		t.Fatal("managed encrypted synthetic context", err)
	}
	verifier, err := objectstore.NewContextVerifier(bound, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	publications := func(role, password string) *postgres.ContextPublications {
		p, err := postgres.NewContextPublications(f.ctx, f.fixturePool(role, password), s.a.RootID, guards)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	check := publications("context_verify_runtime", "synthetic-context-verify")
	ack := publications("context_verification_audit_runtime", "synthetic-context-audit")
	publish := publications("context_publish_runtime", "synthetic-context-publish")
	catalog := publications("context_catalog_read_runtime", "synthetic-context-read")
	f.refreshBase(t)
	publisher := evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: check, ContextVerificationRecorder: check, ContextVerificationAuditor: ack, ContextCatalogPublisher: publish}, Authority: contextPublicationTestGate{check: func(ctx context.Context, v artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
		return f.currentManagedPublication(ctx, s, v)
	}}, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: f.store, Seal: f.keys, Open: f.keys}, Now: time.Now}
	if _, err = publisher.Publish(f.ctx, e.CaptureUID, copies); err != nil {
		t.Fatal("managed independent verification/publication", err)
	}
	processing, err := postgres.NewProcessingReads(f.ctx, f.fixturePool("context_catalog_read_runtime", "synthetic-context-read"), s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	actor := s.a.Eligibility.VerifiedIdentity
	actor.Scopes = []string{"evidence:read", "evidence:download"}
	gate := authapp.ContextDownloadAuthority{RootID: s.a.RootID, Identities: nativeDownloadTestIdentity{value: actor, expires: time.Now().Add(2 * time.Minute)}, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: authapp.CurrentDownloadEnvironment{RootID: s.a.RootID, InstallationID: f.input.InstallationID, Policies: processingTestPolicy{value: f.processingPolicy}, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}, Now: time.Now}
	observation := f.workloadObservation(t, 0)
	if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, observation, enrollment); err != nil {
		t.Fatal(err)
	}
	scope := artifact.DownloadScope{RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(copies), Principal: actor.Principal}
	authority, err := gate.CheckDownload(f.ctx, "synthetic-reference", scope)
	if err != nil {
		t.Fatal("actual managed download authority", err)
	}
	downloads, err := postgres.NewDownloads(f.ctx, f.fixturePool("download_runtime", "synthetic-download"), s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	original := capacityNativeSession(scope, enrollment.DownloadAllocationID, custodyID(), n, identity.Earlier(root.PlannedUntil, authority.AccessUntil))
	session, err := downloads.ReserveDownload(f.ctx, evidence.DownloadReservation{Session: original, IdempotencyDigest: artifact.Digest{27}, Authority: authority})
	if err != nil {
		t.Fatal("actual managed download reservation", err)
	}
	// Charge the original preparation. The fixture deliberately retains its
	// uncertain writer result; renewal may not erase it or refund its spend.
	if _, err = downloads.BeginDownloadBatch(f.ctx, session.ID, authority, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 4 << 20}); err != nil {
		t.Fatal("original managed download charge", err)
	}
	session, err = downloads.LookupDownload(f.ctx, session.ID, actor.Principal)
	if err != nil || session.Requests != 1 || session.ChargedRead <= 0 || session.Generation != 1 {
		t.Fatal("original managed session spend not retained", err)
	}
	snapshot := f.sessionRows(t, session.ID)
	var managed, stopped bool
	if err = f.admin.QueryRow(f.ctx, `SELECT capacity_account_id=$2 AND capacity_backing IS NOT NULL AND octet_length(capacity_backing_digest)=32,EXISTS(SELECT 1 FROM download_stop WHERE download_id=$1) FROM artifact_download WHERE id=$1`, session.ID, enrollment.ID).Scan(&managed, &stopped); err != nil || !managed || !stopped {
		t.Fatal("real session lacks original managed/Stop backing", err)
	}
	f.rejectChangedSessionSnapshot(t, session.ID)
	return capacityManagedSession{session: session, original: snapshot}
}

func (f *capacitySQLFixture) rejectChangedSessionSnapshot(t *testing.T, id string) {
	t.Helper()
	// Exercise actual closed SQL decoding on copies of the real admitted row.
	// No persisted row/trigger is modified to manufacture the negative inputs.
	for _, delta := range []string{
		`jsonb_build_object('capacity_backing',NULL)`,
		`jsonb_build_object('capacity_backing_digest',NULL)`,
		`jsonb_build_object('capacity_backing',s.capacity_backing||'{"unexpected":true}'::jsonb)`,
		`jsonb_build_object('capacity_backing',s.capacity_backing-'Native')`,
	} {
		_, err := f.admin.Exec(f.ctx, `SELECT public.capacity_session_native(jsonb_populate_record(NULL::artifact_download,to_jsonb(s)||`+delta+`),n) FROM artifact_download s JOIN download_native_backing n ON n.allocation_id=s.allocation_id WHERE s.id=$1`, id)
		var driver *pgconn.PgError
		if !errors.As(err, &driver) || driver.Code != "23514" {
			t.Fatalf("malformed managed session fell back to current parent: sqlstate=%s", capacitySQLState(err))
		}
	}
	for _, purpose := range []string{"capacity", "capacity-capture"} {
		_, err := f.roles[purpose].Exec(f.ctx, `UPDATE artifact_download SET capacity_account_id=NULL,capacity_backing=NULL,capacity_backing_digest=NULL WHERE id=$1`, id)
		var driver *pgconn.PgError
		if !errors.As(err, &driver) || driver.Code != "42501" {
			t.Fatalf("capacity role could forge legacy session provenance: purpose=%s sqlstate=%s", purpose, capacitySQLState(err))
		}
	}
}

func (f *capacitySQLFixture) sessionRows(t *testing.T, id string) string {
	t.Helper()
	var b []byte
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object('session',(SELECT to_jsonb(x) FROM artifact_download x WHERE id=$1),'batches',(SELECT jsonb_agg(to_jsonb(x) ORDER BY generation) FROM download_batch x WHERE session_id=$1),'stop',(SELECT to_jsonb(x) FROM download_stop x WHERE download_id=$1),'stop_lifecycle',(SELECT to_jsonb(x) FROM download_stop_lifecycle x WHERE download_id=$1))`, id).Scan(&b)
	if err != nil || !json.Valid(b) {
		t.Fatal("original real managed session read", err)
	}
	return string(b)
}

func (f *capacitySQLFixture) assertOriginalSession(t *testing.T, s capacityManagedSession) {
	t.Helper()
	if f.sessionRows(t, s.session.ID) != s.original {
		t.Fatal("renewal rewrote original session, snapshot, batch, Stop or spend")
	}
	// Both purpose-fixed readers must retain the old cutoff after their current
	// parents have moved forward. This does not mint a new disclosure permit.
	var control, native time.Time
	err := f.admin.QueryRow(f.ctx, `SELECT (public.capacity_session_control(s,c)).valid_until,(public.capacity_session_native(s,n)).valid_until FROM artifact_download s JOIN download_control_allocation c ON c.id=s.allocation_id JOIN download_native_backing n ON n.allocation_id=s.allocation_id WHERE s.id=$1`, s.session.ID).Scan(&control, &native)
	if err != nil || s.session.Deadline.After(control) || s.session.Deadline.After(native) || time.Now().Before(control) || time.Now().Before(native) {
		t.Fatal("effective session reader selected renewed parent dates", err)
	}
	pool := f.fixturePool("capacity_session_projection_fixture", "synthetic-session-projection")
	defer pool.Close()
	var forbidden bool
	if err := pool.QueryRow(f.ctx, `SELECT has_function_privilege(current_user,'capacity_session_native(artifact_download,download_native_backing)','EXECUTE') OR has_function_privilege(current_user,'capacity_session_control(artifact_download,download_control_allocation)','EXECUTE')`).Scan(&forbidden); err != nil || forbidden {
		t.Fatal("projection fixture acquired private helper privilege", err)
	}
	q := custodydb.New(pool)
	n, err := q.ReadSessionNativeBacking(f.ctx, custodydb.ReadSessionNativeBackingParams{ID: capacityProjectionUUID(t, s.session.ID), RootID: capacityProjectionUUID(t, s.session.Scope.RootID)})
	if err != nil {
		t.Fatal("native session projection needs private helper privilege", err)
	}
	c, err := q.ReadDownloadSessionControl(f.ctx, custodydb.ReadDownloadSessionControlParams{ID: capacityProjectionUUID(t, s.session.ID), RootID: capacityProjectionUUID(t, s.session.Scope.RootID)})
	if err != nil {
		t.Fatal("control session projection needs private helper privilege", err)
	}
	var original capacityvalue.CapacitySessionBacking
	if json.Unmarshal(n.CapacityBacking, &original) != nil || !original.Matches(s.session) || !original.Native.ValidUntil.Equal(native) || !original.ControlUntil.Equal(control) || !n.SessionDeadline.Time.Equal(s.session.Deadline) || !c.SessionDeadline.Time.Equal(s.session.Deadline) || string(n.CapacityBacking) != string(c.CapacityBacking) || string(n.CapacityBackingDigest) != string(c.CapacityBackingDigest) || n.CapacityAccountID != c.CapacityAccountID || n.CapacityAccountID != capacityProjectionUUID(t, original.AccountID) {
		t.Fatal("session projection lost original identity, snapshot or cutoff")
	}
}

func capacityProjectionUUID(t *testing.T, text string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := id.Scan(text); err != nil || !id.Valid {
		t.Fatal("invalid projection fixture identity", err)
	}
	return id
}
