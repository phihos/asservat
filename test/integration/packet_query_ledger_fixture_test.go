package integration

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/migrations"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"testing"
	"time"
)

// Each managed root owns a pristine database and closes its pools on return.
// The actual compiled hub/key roles and encrypted audits are real; native
// Job/Pod/issuer/join facts are controlled component inputs, not installed proof.
func TestPacketQueryMetadataLifecycleWithRealServices(t *testing.T) {
	withPacketQueryManagedServices(t, false)
}
func TestPacketQueryRawLifecycleWithRealServices(t *testing.T) {
	withPacketQueryManagedServices(t, true)
}

// These entrypoints must run in separate harness campaigns. Each managed
// capacity fixture requires its own pristine database; no test resets product
// state to make a second root fit the same database.
func withPacketQueryManagedServices(t *testing.T, raw bool) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyPacketQueryManagedLifecycle, false, false, false, true, raw)
	})
}

func qualifyPacketQueryManagedLifecycle(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	ctx, base, s := f.base.ctx, f.base, f.scenario
	root, profile := base.input.PermissionRootID, f.workerProfile
	acquisitionSnapshot := func() string {
		var out string
		if e := base.admin.QueryRow(ctx, `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM access_grant g WHERE root_id=$1 AND capture_id=$2),'sessions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM policy_observation_session p WHERE root_id=$1 AND capture_id=$2),'spend',(SELECT jsonb_agg(to_jsonb(p) ORDER BY grant_id) FROM adhoc_observation_spend p WHERE root_id=$1 AND grant_id IN (SELECT id FROM access_grant WHERE root_id=$1 AND capture_id=$2)),'captures',(SELECT count(*) FROM context_capture WHERE root_id=$1))::text`, root, f.published.Expectation.CaptureUID).Scan(&out); e != nil {
			t.Fatal("acquisition snapshot", e)
		}
		return out
	}
	beforeAcquisition := acquisitionSnapshot()
	qualifySharedProjectionLifecycle(t, f)

	compiled := func(purpose string) *pgxpool.Pool {
		t.Helper()
		pool := base.roles[purpose]
		if pool == nil {
			t.Fatalf("missing compiled installed role %s", purpose)
		}
		return pool
	}
	guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	ledger, err := postgres.NewContextQueries(ctx, compiled("hub-runtime"), root, guards, f.current, nil)
	if err != nil {
		t.Fatal("compiled query ledger", err)
	}
	workers, err := postgres.AttachProjectionWorkers(ledger, profile)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := postgres.NewProjectionNativeOperations(ledger)
	if err != nil {
		t.Fatal(err)
	}
	// A-KEY has its own credential and the same SQL-only backing implementation;
	// it neither opens the hub credential nor invents another capacity producer.
	keyPool := compiled("key-acquisition")
	keyPlans, err := postgres.NewSharedContextQueryPlans(ctx, keyPool, root, base.input.InstallationID, profile)
	if err != nil {
		t.Fatal("compiled key-service backing", err)
	}
	keyLedger, err := postgres.NewContextQueries(ctx, keyPool, root, guards, keyPlans, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = postgres.AttachProjectionWorkers(keyLedger, profile); err != nil {
		t.Fatal(err)
	}
	keyScope := value.KeyScope{InstallationID: base.input.InstallationID, Purpose: "artifact", KeyID: "query-fixture"}
	projectionKeys, err := postgres.NewProjectionKeys(keyLedger, keyScope)
	if err != nil {
		t.Fatal(err)
	}
	// Match key-service startup's actual closed dispatcher. Calling the
	// projection delegate alone misses classification of compact child IDs.
	keys, err := postgres.NewNativeKeyAuthority(ctx, keyPool, root, profile, keyScope, postgres.DownloadTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil || keys.WithProjectionKeys(projectionKeys) != nil {
		t.Fatal("compiled native key authority composition", err)
	}
	metadata := compiled("hub-runtime")
	catalog, err := postgres.NewContextPublications(ctx, metadata, root)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(ctx, metadata, root, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	// This closed workflow's fixture client declares raw results as well as
	// fixed extracts. The shared summary-only producer intentionally declares
	// extract only and remains unchanged.
	recovery, e := s.recovery.reader.RecoveryState(ctx)
	if e != nil {
		t.Fatal(e)
	}
	policySource := packetQueryFixturePolicy{querySQLPolicy{root: root, installation: base.input.InstallationID, epoch: recovery.IssuerEpoch, path: f.profile.Path, packet: true}}
	queryPolicies, e := authapp.NewContextProjectionPolicies(policySource, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	gate := authapp.ContextProjectionAuthority{RootID: root, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: authapp.CurrentProjectionEnvironment{RootID: root, InstallationID: base.input.InstallationID, Policies: queryPolicies, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}, Now: time.Now}
	expected := f.published.Expectation
	scope := query.ContextProjectionScope{RootID: root, CaseID: expected.CaseID, CaptureID: expected.CaptureUID, ArtifactID: expected.Registration.Location.ArtifactID, ClusterID: expected.Registration.Location.ClusterID, NamespaceUID: expected.NamespaceUID, WorkloadUID: expected.WorkloadUID, PodUID: expected.PodUID, Version: evidence.ContextCopiesDigest(f.published.Copies), SourceProjectionDigest: query.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: query.ContextDisplayVersion, Selection: query.LineSelection{LineStart: 1, MaxLines: 14}, Principal: s.a.Plan.Input.Executor}

	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = expected.NativeType, expected.Type().Format, query.PacketQueryDisplayVersion
	scope.SourceProjectionDigest, scope.Selection = artifact.Digest{}, query.LineSelection{}
	selection := query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketCapturedLength, query.PacketWireLength}, MaxPackets: 100, MaxScanBytes: 8 << 20}
	scope.PacketQuery, err = selection.Window()
	if err != nil {
		t.Fatal(err)
	}
	rawPacket := expected.NativeType == artifact.RawPCAPNGArtifact
	var grantStore *postgres.AccessGrants
	if rawPacket {
		grantStore, err = postgres.NewAccessGrants(ctx, compiled("hub-runtime"), root, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		scope.RawGrantID = packetQueryManagedGrant(t, f, grantStore, scope.Principal, scope.Version, 2*query.ContextResultBytes, 2)
		grantService := authapp.GrantService{RootID: root, InstallationID: base.input.InstallationID, Permissions: s.p, Store: grantStore, Recovery: s.recovery.reader, Now: time.Now, NewID: custodyID}
		gate.PacketGrants = grantService
	}
	policy := f.audit.Normal.Policy
	journal, err := postgres.NewHealthyOperationJournal(ctx, compiled("hub-runtime"), policy, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgements, err := postgres.NewOperationAcknowledgements(ctx, compiled("hub-runtime"), root, "normal", s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	completions, err := postgres.NewOperationLifecycles(ctx, compiled("hub-runtime"), root, "normal", s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	closedObjects, err := objectstore.NewClosedOperationAuditObjects(base.store, policy.StoreID, base.keys, base.keys)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := auditapp.NewHealthyOperationAuditor(policy, journal, acknowledgements, &objectstore.OperationAuditObjects{Store: base.store, Seal: base.keys, Open: base.keys}, closedObjects, completions, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	hubProcess := custodyID()
	request := func(tool string) (*sharedProjectionOwner, audit.OperationIntent, context.CancelFunc) {
		t.Helper()
		f.refresh(t)
		n := time.Now().UTC().Truncate(time.Microsecond)
		intent := audit.OperationIntent{ID: custodyID(), RootID: root, TraceID: custodyID(), Name: tool, InputFormat: "context-query-input/v1", MACVersion: "query-fixture-v1", AccountVersion: base.input.AccountVersion, Actor: scope.Principal, PrincipalDigest: artifact.Digest{41}, InputDigest: artifact.Digest{42}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Duration(f.audit.Normal.RetainedSeconds) * time.Second)}
		call, stop := context.WithDeadline(ctx, intent.RequestUntil)
		t.Cleanup(stop)
		if e := auditor.Begin(call, intent); e != nil {
			t.Fatal("real invocation intent", e)
		}
		who := s.a.Eligibility.VerifiedIdentity
		who.Principal = scope.Principal
		who.Scopes = []string{"evidence:read"}
		if rawPacket {
			who.Scopes = append(who.Scopes, "evidence:raw")
		}
		who.VerifiedAt, who.ValidUntil = n, intent.RequestUntil
		var a query.ContextProjectionAuthority
		var e error
		if tool == "pcap_query" {
			a, e = gate.ResolveProjectionCurrent(call, querySQLIdentity{who}, scope.Candidate())
		} else {
			a, e = gate.CheckProjectionCurrent(call, querySQLIdentity{who}, scope)
		}
		if e != nil {
			t.Fatal("actual read-only authority", e)
		}
		a.ValidUntil = identity.Earlier(a.ValidUntil, intent.RequestUntil)
		if !a.Valid(time.Now()) {
			t.Fatal("authority expired during preparation")
		}
		r := query.ContextQueryRequest{Call: query.ContextQueryCall{ID: intent.ID, RootID: root, Tool: tool, InputFormat: intent.InputFormat, MACVersion: intent.MACVersion, InputDigest: intent.InputDigest, PrincipalDigest: intent.PrincipalDigest, Principal: scope.Principal, StartedAt: n, Until: intent.RequestUntil, WriteUntil: intent.WriteUntil}, OwnerID: custodyID(), HubProcessEpoch: hubProcess}
		return &sharedProjectionOwner{ctx: call, request: r, authority: a}, intent, stop
	}
	finish := func(in audit.OperationIntent) {
		t.Helper()
		out := audit.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{61}, OutputBytes: 12, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if e := auditor.Finish(ctx, out); e != nil {
			t.Fatal("real outcome acknowledgement", e)
		}
	}
	enrollment := func(purpose string) *postgres.ProjectionEnrollments {
		t.Helper()
		out, e := postgres.NewProjectionEnrollments(ctx, compiled("hub-runtime"), root, profile, custodyID)
		if e != nil {
			t.Fatal("compiled enrollment", purpose, e)
		}
		return out
	}
	effects := sharedProjectionEnrollmentEffects{ProjectionEnrollments: enrollment("worker-enrollment"), ack: enrollment("worker-enrollment-audit"), activation: enrollment("worker-enrollment-activate")}
	objects := &objectstore.WorkerEnrollmentAuditObjects{Store: base.store, Seal: base.keys, Open: base.keys}
	jobs := &sharedProjectionJobs{podUID: custodyID()}
	admission := evidence.ProjectionWorkerAdmission{Ledger: workers, Jobs: jobs, Audit: objects, Now: time.Now}
	runtime := evidence.ProjectionRuntime{Workers: workers, Identities: workers, Jobs: jobs, Now: time.Now}
	initial, intent, stopInitial := request(scope.BeginTool())
	var q query.ContextQuery

	plan, e := f.current.ContextQueryPlan(initial.ctx, initial.authority)
	if e != nil {
		t.Fatal(e)
	}
	invocation := query.ContextQueryInvocationKey{Key: "packet-query-managed", RequestDigest: artifact.Digest{81}}
	q, err = query.NewContextQuery(custodyID(), intent.ID, custodyID(), initial.authority, plan, time.Now().UTC().Truncate(time.Microsecond), invocation)

	if err != nil {
		t.Fatal(err)
	}
	accepted, err := ledger.AdmitQuery(initial.ctx, q, initial.request, initial.authority)
	if err != nil || !accepted.Fresh {
		t.Fatal("query admission", err)
	}

	stored, found, e := ledger.LookupQueryInvocation(initial.ctx, scope.Principal, invocation.Key, invocation.RequestDigest)
	if e != nil || !found || !stored.Equal(q) {
		t.Fatal("original public-key lookup", found, e)
	}
	if _, _, e = ledger.LookupQueryInvocation(initial.ctx, scope.Principal, invocation.Key, artifact.Digest{82}); !errors.Is(e, query.ErrQueryConflict) {
		t.Fatal("changed public input reused original key", e)
	}
	if rawPacket {
		assertPacketQueryUses(t, f, q.Grant.ParentID, 0, 0)
	}
	if err = admission.AdmitProjectionWorker(initial.ctx, q, initial); err != nil {
		t.Fatal("reserve/audit/claim/Job", err)
	}
	pending, err := runtime.ObserveProjectionWorker(initial.ctx, q, initial)
	if err != nil || pending.Ready || !jobs.worker.Valid() {
		t.Fatal("bind admitted worker before enrollment", pending, err)
	}
	// Exact replay can observe the retained Job but cannot issue another create.
	if err = admission.AdmitProjectionWorker(initial.ctx, q, initial); err != nil || jobs.creates != 1 || jobs.finds != 1 {
		t.Fatal("worker replay", jobs.creates, jobs.finds, err)
	}
	finish(intent)
	stopInitial()
	if initial.ctx.Err() == nil {
		t.Fatal("original human operation did not close")
	}
	// This independent admitted-worker request must need no live human owner.
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	issuer := sharedProjectionIssuer{newSyntheticWorkerIssuer(t, base.input.InstallationID)}
	enrollmentService := evidence.ProjectionEnrollmentCoordinator{CSR: mtls.EnrollmentProof{}, Proofs: sharedProjectionProof{jobs.worker}, Ledger: effects, Audit: objects, Issuer: issuer, Now: time.Now}
	parent := value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}
	// A new worker request observes current sources; admitted dates stay fixed.
	f.refresh(t)
	cert, err := enrollmentService.EnrollProjection(ctx, parent, q.WorkerID, csr)
	if err != nil || !cert.Peer.Valid(time.Now()) {
		t.Fatal("identity enrollment after human request closed", err)
	}
	again, err := enrollmentService.EnrollProjection(ctx, parent, q.WorkerID, csr)
	if err != nil || again.Peer != cert.Peer || issuer.calls.Load() != 1 {
		t.Fatal("certificate replay changed identity/sign count", issuer.calls.Load(), err)
	}

	var lastBatch query.ContextReadBatch
	for generation := 1; generation <= 2; generation++ {
		poll, pollIntent, stopPoll := request("get_query_result")
		defer stopPoll()
		a, r := poll.authority, poll.request
		if err = ledger.AdmitQueryPoll(poll.ctx, q, r, a); err != nil {
			t.Fatal("fresh read-only poll", err)
		}
		ready, err := runtime.ObserveProjectionWorker(poll.ctx, q, poll)
		if err != nil || !ready.Ready || ready.Worker.QueryID != q.ID || ready.Worker.Certificate != cert.Peer.Certificate {
			t.Fatal("actual activated identity", ready, err)
		}
		if rawPacket && generation == 1 {
			packetQueryBatchRollback(t, f, compiled("hub-runtime"), q, r, ready.Worker, a)
			assertPacketQueryUses(t, f, q.Grant.ParentID, 0, 0)
		}
		batch, err := ledger.BeginReadBatch(poll.ctx, q, r, ready.Worker, custodyID(), a)
		if err != nil || !batch.Fresh {
			t.Fatal("compiled batch admission", err)
		}

		replay, e := ledger.BeginReadBatch(poll.ctx, q, r, ready.Worker, batch.Batch.ID, a)
		if e != nil || replay.Fresh || !replay.Batch.Equal(batch.Batch) {
			t.Fatal("same batch replay changed reservation", e)
		}
		if rawPacket {
			assertPacketQueryUses(t, f, q.Grant.ParentID, int64(generation)*query.ContextResultBytes, int64(generation))
		}
		start, err := ledger.ClaimReadBatch(poll.ctx, batch.Batch, a)
		if err != nil || !start.Fresh {
			t.Fatal("compiled one-use batch claim", err)
		}
		second, err := ledger.ClaimReadBatch(poll.ctx, batch.Batch, a)
		if err != nil || second.Fresh {
			t.Fatal("batch replay refilled start", err)
		}
		publicKey, err := mtls.EnrollmentKey(csr)
		if err != nil {
			t.Fatal(err)
		}
		n := time.Now().UTC().Truncate(time.Microsecond)
		operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: base.input.InstallationID, QueryID: q.ID, WorkerID: q.WorkerID, OperationID: start.Batch.ID, Fence: start.Batch.Generation}, Kind: value.NativeProjection, HubPodUID: custodyID(), HubProcessEpoch: r.HubProcessEpoch, WorkerPodUID: jobs.worker.Binding.PodUID, WorkerPublicKey: publicKey, SourceVersion: q.Scope.Version, ParentID: start.Batch.ID, Generation: start.Batch.Generation, StartedAt: n, Until: identity.Earlier(start.Batch.Until, a.ValidUntil), Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing}

		if err = operations.ClaimProjectionNative(poll.ctx, start, a, operation); err != nil {
			t.Fatal("compiled native operation", err)
		}
		lease, err := operations.ObserveProjectionNativeOperation(poll.ctx, operation.Reference, cert.Peer)
		if err != nil {
			t.Fatal("current native operation", err)
		}
		swapped := operation.Reference
		swapped.QueryID = custodyID()
		if _, err = operations.ObserveProjectionNativeOperation(poll.ctx, swapped, cert.Peer); err == nil {
			t.Fatal("certificate authorized another query")
		}

		source, e := operations.ReadProjectionSource(poll.ctx, q, a, r)
		if e != nil || !source.Valid(scope.Version) || evidence.ContextExpectationDigest(source.Expectation) != evidence.ContextExpectationDigest(expected) {
			t.Fatal("actual pinned packet source", e)
		}

		proof := value.AcquisitionPeerProof{Binding: jobs.worker.Binding, Peer: cert.Peer, TokenDigest: artifact.Digest{7}, ObservedAt: n, FreshUntil: identity.Earlier(n.Add(5*time.Second), cert.Peer.NotAfter)}
		if err = operations.BindProjectionNativeKeys(poll.ctx, start, a, operation, keyScope, evidence.NativeOrigin{Lease: lease, Proof: proof}); err != nil {
			t.Fatal("compiled exact query key binding", err)
		}
		// Preserve the actual process boundary: hub binding cannot consume keys,
		// and A-KEY cannot manufacture a new child even with valid current facts.
		for _, negative := range []struct {
			pool *pgxpool.Pool
			sql  string
		}{
			{compiled("hub-runtime"), "UPDATE context_query_key_binding SET used_roles=1 WHERE batch_id=$1"},
			{keyPool, "INSERT INTO context_query_key_binding SELECT * FROM context_query_key_binding WHERE batch_id=$1 AND false"},
			{keyPool, "SELECT id FROM access_grant WHERE id=$1"},
			{keyPool, "UPDATE access_grant SET bytes_spent=bytes_spent WHERE id=$1"},
		} {
			_, e := negative.pool.Exec(poll.ctx, negative.sql, start.Batch.ID)
			var denied *pgconn.PgError
			if !errors.As(e, &denied) || denied.Code != "42501" {
				t.Fatal("compiled hub/key process boundary", e)
			}
		}
		keyIDs := []string{start.Batch.ID}

		for ordinal, keyID := range keyIDs {
			// Framed native reads authenticate the manifest, then framed.Open
			// opens data and index keys. Cover 4 -> 5 -> 7, not just 1 -> 3 -> 7.
			for _, role := range []query.ContextProjectionKeyRole{query.ContextProjectionManifestKey, query.ContextProjectionDataKey, query.ContextProjectionIndexKey} {
				binding, e := evidence.ArtifactKeyBinding(expected.Binding(), string(role))
				if e != nil {
					t.Fatal(e)
				}
				// The fixture's object encryption uses authorityTestKeys. This scoped
				// reference exercises SQL authorization, not a production key unwrap.
				request := value.KeyRequestInfo{Scope: keyScope, Operation: "unwrap", AuthorityID: keyID, RequestDigest: artifact.Digest{byte(role.Mask())}, Binding: binding, Reference: "asservat-local-keyset/v1/" + keyScope.InstallationID + "/artifact/" + keyScope.KeyID + "/1"}
				wrong := request
				wrong.AuthorityID = custodyID()
				if _, e = keys.Resolve(poll.ctx, cert.Peer, wrong); e == nil {
					t.Fatal("unknown key authority dispatched")
				}
				wrong = request
				wrong.Binding = []byte("different-source-binding")
				if _, e = keys.Resolve(poll.ctx, cert.Peer, wrong); e == nil {
					t.Fatal("wrong source AAD consumed a role")
				}
				wrongPeer := cert.Peer
				wrongPeer.Certificate[0] ^= 1
				if _, e = keys.Resolve(poll.ctx, wrongPeer, request); e == nil {
					t.Fatal("different worker certificate consumed a role")
				}

				permit, e := keys.Resolve(poll.ctx, cert.Peer, request)
				if e != nil || !permit.Valid(cert.Peer, request, time.Now()) {
					t.Fatal("compiled native key authority role", ordinal, role, e)
				}
				if _, e = keys.Resolve(poll.ctx, cert.Peer, request); e == nil {
					t.Fatal("used key role was replenished", ordinal, role)
				}
			}
		}
		if err = ledger.CompleteReadBatch(poll.ctx, start.Batch, querySQLClosed{start.Batch}); err == nil {
			t.Fatal("private closure without outcome acknowledgement released batch")
		}
		// This SQL qualifier supplies the positive transport-join input explicitly.
		if err = operations.CompleteProjectionNative(poll.ctx, lease); err != nil {
			t.Fatal("record positive private native close", err)
		}
		finish(pollIntent)
		if err = ledger.CompleteReadBatch(ctx, start.Batch, querySQLClosed{start.Batch}); err != nil {
			t.Fatal("closed batch after real encrypted outcome", err)
		}
		lastBatch = start.Batch
		if generation == 2 {
			if _, e := ledger.BeginReadBatch(poll.ctx, q, r, ready.Worker, custodyID(), a); e == nil {
				t.Fatal("third page was admitted")
			}
		}

	}

	var downloads, workersCount, certificates, keyRoles, keyChildren, queries, allocated int64
	var nativeClosed, closed, active, audited, claimed, bound bool
	if err = base.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM artifact_download),
 (SELECT count(*) FROM download_worker WHERE query_id=$1 AND session_id IS NULL),
 (SELECT count(*) FROM download_worker_certificate WHERE worker_id=$2 AND activated_at IS NOT NULL AND audit_receipt_json IS NOT NULL),
 (SELECT sum(used_roles) FROM context_query_key_binding WHERE batch_id=$3),
 (SELECT count(*) FROM context_query_key_binding WHERE batch_id=$3),
 (SELECT count(*) FROM context_query WHERE root_id=$4),(SELECT allocated FROM context_query_backing WHERE root_id=$4),
 b.native_closed,b.closed,q.active_batch IS NOT NULL,w.audit_receipt_json IS NOT NULL,w.claimed_at IS NOT NULL,w.binding_json IS NOT NULL
 FROM context_query_batch b JOIN context_query q ON q.id=b.query_id JOIN download_worker w ON w.id=q.worker_id WHERE b.id=$3`, q.ID, q.WorkerID, lastBatch.ID, root).Scan(&downloads, &workersCount, &certificates, &keyRoles, &keyChildren, &queries, &allocated, &nativeClosed, &closed, &active, &audited, &claimed, &bound); err != nil {
		t.Fatal("independent final state", err)
	}
	if downloads != 0 || workersCount != 1 || certificates != 1 || keyRoles != 7 || keyChildren != 1 || queries != 2 || allocated != 2+scope.QueryUnits() || !nativeClosed || !closed || active || !audited || !claimed || !bound {
		t.Fatalf("unexpected paid final state: downloads=%d workers=%d certificates=%d roles=%d children=%d queries=%d allocated=%d nativeClosed=%t closed=%t active=%t audited=%t claimed=%t bound=%t", downloads, workersCount, certificates, keyRoles, keyChildren, queries, allocated, nativeClosed, closed, active, audited, claimed, bound)
	}

	var batches, roles, children int
	if e := base.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM context_query_batch WHERE query_id=$1 AND native_closed AND closed),(SELECT coalesce(sum(used_roles),0) FROM context_query_key_binding WHERE query_id=$1),(SELECT count(*) FROM context_query_key_binding WHERE query_id=$1)`, q.ID).Scan(&batches, &roles, &children); e != nil || batches != 2 || roles != 14 || children != 2 {
		t.Fatal("two fully consumed and closed page batches", batches, roles, children, e)
	}
	if acquisitionSnapshot() != beforeAcquisition {
		t.Fatal("query changed acquisition/observation debit or made a new capture")
	}
	if rawPacket {
		assertPacketQueryUses(t, f, q.Grant.ParentID, 2*query.ContextResultBytes, 2)
		// Exhausted disclosure does not erase the exact original child/query. A
		// separately named native use competes on the SAME pool and must be denied.
		recovery, e := s.recovery.reader.RecoveryState(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, _, e = grantStore.ReserveGrantUse(ctx, authapp.GrantUseRequest{UseID: custodyID(), ParentID: q.Grant.ParentID, ChildID: q.Grant.ChildID, Use: value.GrantUse{Operation: value.GrantDownloadOperation, Bytes: 1, Operations: 1}}, recovery)
		if e == nil {
			t.Fatal("native disclosure did not compete with spent packet-page pool")
		}
	}
	if rawPacket {
		var live bool
		if e := keyPool.QueryRow(ctx, "SELECT context_packet_query_grant_current($1,$2,$3)", root, q.ID, lastBatch.ID).Scan(&live); e != nil || !live {
			t.Fatal("spent batch not current before revoke", e)
		}
		currentRecovery, e := s.recovery.reader.RecoveryState(ctx)
		if e != nil {
			t.Fatal(e)
		}
		currentParent, e := grantStore.Grant(ctx, q.Grant.ParentID)
		if e != nil {
			t.Fatal(e)
		}
		revoked, _, e := grantStore.RevokeGrant(ctx, authapp.GrantRevocationInput{GrantID: currentParent.ID, Revoker: scope.Principal, ExpectedRevision: currentParent.Revision, IdempotencyKey: "revoke-query-original"}, currentRecovery)
		if e != nil || revoked.RevokedAt.IsZero() {
			t.Fatal("original query grant revoke", e)
		}
		if e = keyPool.QueryRow(ctx, "SELECT context_packet_query_grant_current($1,$2,$3)", root, q.ID, lastBatch.ID).Scan(&live); e != nil || live {
			t.Fatal("isolated key predicate ignored current revocation", e)
		}
	}
	refuseRetainedPacketQueryDowngrade(t, f)

	stored, err = ledger.LookupQuery(ctx, scope.Principal, q.ID)
	if err != nil || !stored.Equal(q) {
		t.Fatal("lifecycle changed original query/deadlines", err)
	}
	t.Log("compiled packet-query lifecycle: existing summary retained; four query units/two page batches, same public key/deadlines, raw pages each24KiB/one operation, actual hub/key roles and six consumed roles; native+public close; Job/Pod/issuer/join inputs synthetic")
}

func packetQueryManagedGrant(t *testing.T, f *queryLedgerFixture, store *postgres.AccessGrants, actor identity.Principal, version artifact.Digest, maxBytes, ops int64) string {
	t.Helper()
	ctx := f.base.ctx
	e := f.published.Expectation
	recovery, err := f.scenario.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	output := value.VerifiedOutput{CaptureID: e.CaptureUID, ActionID: e.ActionID, ArtifactID: e.Registration.Location.ArtifactID, ExecutionDigest: e.PlanDigest, ArtifactDigest: version, Target: value.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}}
	raw := value.RawQueryScope{CaseID: e.CaseID, Artifacts: []value.RawQueryArtifact{{Output: output, NativeBytes: 0, ExpiresAt: e.Registration.ExpiresAt}}, Operations: []string{value.GrantDownloadOperation, value.GrantPacketQueryOperation}, Reason: "Review existing synthetic packet source", MaxBytes: maxBytes, MaxOperations: ops, NotAfter: now.Add(time.Minute)}
	// Derive immutable verified length from the already published verification row.
	if err = f.base.admin.QueryRow(ctx, "SELECT native_bytes FROM context_verification WHERE root_id=$1 AND capture_id=$2", f.base.input.PermissionRootID, e.CaptureUID).Scan(&raw.Artifacts[0].NativeBytes); err != nil {
		t.Fatal(err)
	}
	g := value.Grant{ID: custodyID(), RootID: f.base.input.PermissionRootID, Kind: value.GrantRawQuery, RawQuery: &raw, DataClass: "raw", Requester: actor, Lifetime: time.Minute, Revision: 1, Reasons: []value.SensitiveReason{{ActionID: value.GrantPacketQueryOperation, Code: "rawDisclosure"}}}
	g.Scope, g.ExecutionDigest = authapp.RawQueryScopeBytes(raw)
	g.Review = []byte(`{"fixture":"exact accepted saved packet"}`)
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	pending, _, err := store.RequestGrant(ctx, authapp.StoredGrantRequest{Grant: g, IdempotencyKey: "packet-query-grant", RequestDigest: artifact.Digest{73}}, recovery)
	if err != nil {
		t.Fatal("actual raw query review request", err)
	}
	lead := actor
	lead.Subject += "-independent-reviewer"
	approved, _, err := store.DecideGrant(ctx, authapp.GrantDecisionInput{GrantID: pending.ID, Approve: true, Approver: lead, Reason: "independent exact source/query/download review", ACR: "synthetic-stepup", AuthTime: now, IdempotencyKey: "approve-packet-query"}, recovery)
	if err != nil {
		t.Fatal("independent packet query decision", err)
	}
	return approved.ID
}
func assertPacketQueryUses(t *testing.T, f *queryLedgerFixture, parent string, wantBytes, wantOps int64) {
	t.Helper()
	var usedBytes, usedOps, count, rows int64
	err := f.base.admin.QueryRow(f.base.ctx, `SELECT g.bytes_spent,g.operations_spent,(SELECT count(*) FROM access_grant_use u WHERE u.root_id=g.root_id AND u.parent_id=g.id AND u.operation='pcap_query'),(SELECT count(*) FROM context_query_batch b JOIN context_query q ON q.id=b.query_id JOIN access_grant_use u ON u.id=b.id AND u.root_id=q.root_id WHERE u.parent_id=g.id AND u.child_id::text=q.query#>>'{Grant,ChildID}' AND u.operation='pcap_query' AND u.bytes=24576 AND u.operations=1) FROM access_grant g WHERE root_id=$1 AND id=$2`, f.base.input.PermissionRootID, parent).Scan(&usedBytes, &usedOps, &count, &rows)
	if err != nil || usedBytes != wantBytes || usedOps != wantOps || count != wantOps || rows != count {
		t.Fatalf("per actual batch debit bytes=%d/%d operations=%d/%d uses=%d joinedbatches=%d err=%v", usedBytes, wantBytes, usedOps, wantOps, count, rows, err)
	}
}
func refuseRetainedPacketQueryDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.base.admin.Config().ConnConfig)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.DownTo(f.base.ctx, 138); err == nil {
		t.Fatal("retained packet query/grant/use downgraded")
	}
	var head int64
	if err = f.base.admin.QueryRow(f.base.ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&head); err != nil || head != 139 {
		t.Fatal("refused downgrade changed head", head, err)
	}
	t.Log("retained139 packet query/grant/use prevents138 rollback, no spend refund")
}

// Compiled hub role, same existing UPDATE/use/INSERT statements: a bad batch
// generation must roll back its preceding irreversible-use writes atomically.
func packetQueryBatchRollback(t *testing.T, f *queryLedgerFixture, pool *pgxpool.Pool, q query.ContextQuery, r query.ContextQueryRequest, w query.ContextQueryWorker, a query.ContextProjectionAuthority) {
	t.Helper()
	ctx := f.base.ctx
	batchID := custodyID()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `UPDATE access_grant SET bytes_spent=bytes_spent+24576,operations_spent=operations_spent+1 WHERE root_id=$1 AND id=$2`, q.Scope.RootID, q.Grant.ParentID); err != nil {
		t.Fatal("rollback setup charge", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO access_grant_use(id,root_id,parent_id,child_id,operation,bytes,operations) VALUES($1,$2,$3,$4,'pcap_query',24576,1)`, batchID, q.Scope.RootID, q.Grant.ParentID, q.Grant.ChildID); err != nil {
		t.Fatal("rollback setup use", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	bad := query.ContextReadBatch{ID: batchID, QueryID: q.ID, OperationID: r.Call.ID, Generation: 2, Worker: w, Request: r, StartedAt: now, Until: identity.Earlier(q.Deadline, identity.Earlier(r.Call.Until, a.ValidUntil)), CleanupUntil: q.CleanupUntil}
	encoded, _ := json.Marshal(bad)
	_, err = tx.Exec(ctx, `INSERT INTO context_query_batch(id,query_id,operation_id,generation,batch) VALUES($1,$2,$3,2,$4)`, batchID, q.ID, r.Call.ID, encoded)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "23514" {
		t.Fatal("invalid batch did not reject entire debit transaction", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var uses int
	if err = f.base.admin.QueryRow(ctx, "SELECT count(*) FROM access_grant_use WHERE root_id=$1 AND id=$2", q.Scope.RootID, batchID).Scan(&uses); err != nil || uses != 0 {
		t.Fatal("failed batch left a use", uses, err)
	}
}

type packetQueryFixturePolicy struct{ querySQLPolicy }

func (p packetQueryFixturePolicy) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	out, err := p.querySQLPolicy.DownloadPolicy(ctx)
	if err != nil {
		return out, err
	}
	for i := range out.Clients {
		out.Clients[i].DataClasses = []string{"extract", "raw"}
	}
	return out, nil
}
