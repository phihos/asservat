package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyCapacityAccountsSQL covers capacity_apply, on-demand enrollment,
// burst charges within the hard limit and the pool, and release back to the
// protected share.
func qualifyCapacityAccountsSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	if !t.Run("lifecycle-policy-timestamp-wire", func(t *testing.T) { qualifyCapacityPolicyTimestampSQL(t, ctx, admin) }) {
		t.FailNow()
	}
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
	root, e := f.setup(t)
	const mib = int64(1 << 20)
	type state struct{ limit, charged, pool, accounts, bindings, revision int64 }
	read := func() state {
		t.Helper()
		var s state
		if err := admin.QueryRow(ctx, `SELECT a.byte_limit,a.charged_bytes,p.allocated_bytes,
 (SELECT count(*) FROM capacity_account WHERE root_id=$2),
 (SELECT count(*) FROM context_storage_binding WHERE root_id=$2 AND allocation_id=a.id),
 (SELECT revision FROM capacity_settings WHERE root_id=$2)
 FROM custody_allocation a JOIN custody_pool p ON p.id=a.pool_id WHERE a.id=$1`, e.AllocationID, f.input.PermissionRootID).Scan(&s.limit, &s.charged, &s.pool, &s.accounts, &s.bindings, &s.revision); err != nil {
			t.Fatal("capacity state", err)
		}
		return s
	}
	if s := read(); s != (state{limit: mib, pool: mib, accounts: 1, bindings: 1, revision: 1}) {
		t.Fatal("enrollment did not create one protected share and binding", s)
	}
	// A second apply changes only the values.
	values := f.values
	values.LimitBytes = 3 * mib
	q, err := postgres.ApplyCapacity(ctx, f.roles["capacity"], f.input.ControlClusterID, f.input.ControlNamespaceUID, f.qualification, values)
	if err != nil || q.ID != f.qualification.ID || q.Digest != f.qualification.Digest {
		t.Fatal("second capacity apply", err)
	}
	if s := read(); s != (state{limit: mib, pool: mib, accounts: 1, bindings: 1, revision: 2}) {
		t.Fatal("second apply changed accounts", s)
	}
	if again := f.enroll(t, f.input.ControlClusterID, f.namespace, f.workloads[0]); again != e {
		t.Fatal("repeated storage read enrolled another account", again, e)
	}
	call := func(fn string, bytes int64) bool {
		t.Helper()
		var ok bool
		if err := admin.QueryRow(ctx, `SELECT public.`+fn+`($1,$2,0)`, e.AllocationID, bytes).Scan(&ok); err != nil {
			t.Fatal(fn, err)
		}
		return ok
	}
	steps := []struct {
		fn    string
		bytes int64
		ok    bool
		want  state
	}{
		{"capacity_charge", mib, true, state{limit: mib, charged: mib, pool: mib}},
		{"capacity_charge", mib, true, state{limit: 2 * mib, charged: 2 * mib, pool: 2 * mib}},      // burst
		{"capacity_charge", 2 * mib, false, state{limit: 2 * mib, charged: 2 * mib, pool: 2 * mib}}, // above the hard limit
		{"capacity_release", mib, true, state{limit: mib, charged: mib, pool: mib}},                 // burst returns to the pool
		{"capacity_release", mib, true, state{limit: mib, pool: mib}},                               // the protected share stays
	}
	for i, step := range steps {
		if ok := call(step.fn, step.bytes); ok != step.ok {
			t.Fatal("step", i, step.fn, ok)
		}
		step.want.accounts, step.want.bindings, step.want.revision = 1, 1, 2
		if s := read(); s != step.want {
			t.Fatal("step", i, step.fn, s, step.want)
		}
	}
	// An update to a lower share and limit keeps charged bytes, refuses new
	// charges above the new limit and releases back to the new share.
	apply := func(v app.CapacityValues) {
		t.Helper()
		if _, err := postgres.ApplyCapacity(ctx, f.roles["capacity"], f.input.ControlClusterID, f.input.ControlNamespaceUID, f.qualification, v); err != nil {
			t.Fatal("capacity update", err)
		}
	}
	protected := func() int64 {
		t.Helper()
		var b int64
		if err := admin.QueryRow(ctx, `SELECT protected_bytes FROM capacity_account WHERE allocation_id=$1`, e.AllocationID).Scan(&b); err != nil {
			t.Fatal("protected share", err)
		}
		return b
	}
	if !call("capacity_charge", 3*mib) {
		t.Fatal("charge up to the hard limit refused")
	}
	lower := values
	lower.ShareBytes, lower.LimitBytes = mib/2, 2*mib
	apply(lower)
	if s := read(); s != (state{limit: 3 * mib, charged: 3 * mib, pool: 3 * mib, accounts: 1, bindings: 1, revision: 3}) || protected() != mib/2 {
		t.Fatal("lower update dropped charged bytes", s)
	}
	if call("capacity_charge", 1) {
		t.Fatal("charge above the lowered limit admitted")
	}
	if !call("capacity_release", 3*mib) {
		t.Fatal("release refused")
	}
	if s := read(); s != (state{limit: mib / 2, pool: mib / 2, accounts: 1, bindings: 1, revision: 3}) {
		t.Fatal("release did not return to the new share", s)
	}
	apply(f.values)
	f.managedContextDownload(t, root, e)
}

// managedContextDownload admits, publishes and reserves a download for one
// context through the enrolled account's allocations.
func (f *capacitySQLFixture) managedContextDownload(t *testing.T, root capacityRoot, enrollment capacityEnrollment) {
	t.Helper()
	f.initializeManagedProcessing(t, root)
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
	guards := s.retention.guard
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
	f.qualifySharedMetadataReaders(t, s, e, enrollment)
	processing, err := postgres.NewProcessingReads(f.ctx, f.fixturePool("context_catalog_read_runtime", "synthetic-context-read"), s.a.RootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	actor := s.a.Eligibility.VerifiedIdentity
	actor.Scopes = []string{"evidence:read", "evidence:download"}
	gate := authapp.ContextDownloadAuthority{RootID: s.a.RootID, Identities: nativeDownloadTestIdentity{value: actor, expires: time.Now().Add(2 * time.Minute)}, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: authapp.CurrentDownloadEnvironment{RootID: s.a.RootID, InstallationID: f.input.InstallationID, Policies: processingTestPolicy{value: f.processingPolicy}, Processing: processing, Now: time.Now}, Now: time.Now}
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
	if _, err = downloads.BeginDownloadBatch(f.ctx, session.ID, authority, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 4 << 20}); err != nil {
		t.Fatal("original managed download charge", err)
	}
	session, err = downloads.LookupDownload(f.ctx, session.ID, actor.Principal)
	if err != nil || session.Requests != 1 || session.ChargedRead <= 0 || session.AllocationID != enrollment.DownloadAllocationID {
		t.Fatal("managed session spend not retained", err)
	}
}
