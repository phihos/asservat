package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This qualifies actual purpose-separated SQL/S3/Tink composition and the
// completed-result publication gate. Native workload/process proof and local
// start receipts remain explicit synthetic fixtures here; separate Kubernetes
// qualification is mandatory before this runner can be deployed.
func qualifyAPIExecutionTransactions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	qualifyAPIExecutionPreparationBoundaries(t, ctx, admin, poolFor, store, keys, create)
	qualifyAPIExecutionRetainedObservation(t, ctx, admin, poolFor, store, keys, create)
	t.Run("api-execution-one-preparation-exact-result-historical-publication", func(t *testing.T) {
		// Qualify each compiled publication role independently. Each child gets
		// a fresh execution and reaches its first publication effects without a
		// successful fixture-role fallback or a previously recorded verdict.
		for _, roleCase := range []struct{ name, purpose string }{
			{"compiled-verifier", "context-verify"},
			{"compiled-publisher", "context-publish"},
		} {
			t.Run(roleCase.name, func(t *testing.T) {
				s := create(t, 1)
				in := s.a.Plan.Input
				in.CaseID = s.a.CaseID
				in.Target.ExecutionClass = artifact.ContextAPIExecution
				in.Capability.ExecutionClass = artifact.ContextAPIExecution
				in.Target.NodeUID = ""
				in.Target.NodeBootID = ""
				in.Target.Pin.NodeName = ""
				var err error
				s.a.Plan, err = planning.CompileContext(in, s.a.Plan.CompiledAt)
				if err != nil {
					t.Fatal(err)
				}
				accepted, err := s.s.AdmitContext(ctx, s.a)
				if err != nil {
					t.Fatal(err)
				}
				initializeProcessingTestFixture(t, ctx, poolFor, store, keys, s, accepted.Expectation)
				pool := func(user, password string) *pgxpool.Pool { p := poolFor(user, password); t.Cleanup(p.Close); return p }
				sharedPools, _ := compiledOrdinaryHubPools(t, ctx, admin, poolFor)
				sharedPool := sharedPools.ordinary
				qualifyOrdinaryHubPoolBound(t, ctx, sharedPools)
				for _, query := range []string{
					"DELETE FROM context_execution WHERE false",
					"UPDATE context_execution SET binding_json=binding_json WHERE false",
					"INSERT INTO context_capture SELECT * FROM context_capture WHERE false",
					"UPDATE context_capture SET expectation_json=expectation_json WHERE false",
					"UPDATE fleet_trust SET recovery_blocked=false WHERE false",
					"INSERT INTO context_catalog(artifact_id,capture_id,root_id) SELECT id,id,root_id FROM context_capture WHERE false",
					"UPDATE custody_copy SET etag=etag WHERE false",
					"INSERT INTO context_key_unwrap SELECT * FROM context_key_unwrap WHERE false",
					"DELETE FROM authority_audit WHERE false",
				} {
					if _, err = sharedPool.Exec(ctx, query); capacitySQLState(err) != "42501" {
						t.Fatal("execution credential acquired excluded authority", query, err)
					}
				}
				guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
				newExecution := func(p *pgxpool.Pool) *postgres.APIContextExecutions {
					x, e := postgres.NewAPIContextExecutions(ctx, p, s.a.RootID, guards)
					if e != nil {
						t.Fatal(e)
					}
					return x
				}
				executionSQL := newExecution(sharedPool)
				prepare, execute, read := executionSQL, executionSQL, executionSQL
				intents, err := postgres.NewCaptureIntentAudits(ctx, pool("capture_audit_runtime", "synthetic-capture-audit"), s.a.RootID)
				if err != nil {
					t.Fatal(err)
				}
				if err = (auditapp.CaptureIntentPublisher{Ledger: intents, Objects: &objectstore.CaptureIntentObjects{Store: store, Seal: keys, Open: keys}}).PublishCaptureIntents(ctx); err != nil {
					t.Fatal(err)
				}
				// ADR-176: the executor Pod is also the connector process whose client
				// leaf wraps this attempt's keysets.
				executorPod := custodyID()
				refresh := func() executionapp.APIExecutionCheck {
					n := time.Now().UTC().Truncate(time.Microsecond)
					s.batch.ObservedAt = n
					s.batch.FreshUntil = n.Add(5 * time.Second)
					s.batch.Initial = nil
					if err := s.p.RefreshPermissions(ctx, s.batch); err != nil {
						t.Fatal(err)
					}
					identity := s.a.Eligibility.VerifiedIdentity
					identity.VerifiedAt = n
					identity.ValidUntil = n.Add(5 * time.Second)
					recovery, err := s.recovery.reader.RecoveryState(ctx)
					if err != nil {
						t.Fatal(err)
					}
					work, err := read.ReadAPIContextWork(ctx, accepted.CaptureID, identity, recovery)
					if err != nil {
						t.Fatal(err)
					}
					projection, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
					if err != nil {
						t.Fatal(err)
					}
					eligible := authorization.ContextEligibility(identity, projection, s.a.Eligibility.Target, time.Now())
					policies, err := s.retention.policies(ctx)
					if err != nil {
						t.Fatal(err)
					}
					retention, err := privacy.Resolve(policies, privacy.Input{Target: s.a.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, AnchorAt: accepted.Expectation.Registration.AnchorAt}, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					input := s.a.Plan.Input
					input.Target.ObservedAt = n
					input.Target.FreshUntil = n.Add(5 * time.Second)
					input.Capability.ObservedAt = n
					input.Capability.FreshUntil = n.Add(5 * time.Second)
					input.Retention = retention
					plan, err := planning.CompileContext(input, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					process := value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: recovery.InstallationID, ClusterID: input.Target.Target().ClusterID, IssuerEpoch: recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: executorPod, ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: accepted.Expectation.CollectorImageDigest}, CheckedAt: n, ValidUntil: n.Add(5 * time.Second)}
					until := n.Add(5 * time.Second)
					for _, d := range []time.Time{eligible.ValidUntil, plan.ValidUntil, recovery.FreshUntil, process.ValidUntil} {
						if d.Before(until) {
							until = d
						}
					}
					return executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligible, Recovery: recovery, Process: process, CheckedAt: n, ValidUntil: until.Truncate(time.Microsecond)}
				}
				c := refresh()
				if !c.Valid(time.Now()) {
					t.Fatal("invalid synthetic preparation observation")
				}
				var wg sync.WaitGroup
				results := make(chan value.APIExecution, 8)
				fresh := make(chan bool, 8)
				errs := make(chan error, 8)
				for range 8 {
					wg.Go(func() { r, first, e := prepare.PrepareAPIExecution(ctx, c); results <- r; fresh <- first; errs <- e })
				}
				wg.Wait()
				close(results)
				close(fresh)
				close(errs)
				for e := range errs {
					if e != nil {
						t.Fatal(e)
					}
				}
				count := 0
				for b := range fresh {
					if b {
						count++
					}
				}
				if count != 1 {
					t.Fatal("multiple first acknowledgements", count)
				}
				var execution value.APIExecution
				for r := range results {
					if execution.Phase != "" && execution != r {
						t.Fatal("replay changed immutable start")
					}
					execution = r
				}
				other := c
				other.Process.Binding.ProcessEpoch = custodyID()
				if _, _, err = prepare.PrepareAPIExecution(ctx, other); err == nil {
					t.Fatal("new process inherited old preparation")
				}
				wraps := qualifyContextKeyWraps(t, ctx, admin, poolFor, store, keys, s, accepted.Expectation, c.Process.Binding)
				execution, err = prepare.BindAPIStart(ctx, c, execution, value.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = wraps.resolve(ctx, "index-key"); err == nil {
					t.Fatal("wrap after the start object was bound")
				}
				d := value.Disposition{ObjectUID: execution.ObjectUID, ResourceVersion: "2", Phase: value.StartCommitted, CommittedAt: time.Now().UTC().Truncate(time.Microsecond), MayStart: true, ValidUntil: execution.Binding.NotAfter}
				execution, err = execute.RecordAPIStart(ctx, c, execution, d)
				if err != nil {
					t.Fatal(err)
				}
				bound, err := store.ForCustody(accepted.Expectation.Registration.StoreID)
				if err != nil {
					t.Fatal(err)
				}
				producer, err := objectstore.NewContextProducer(bound, keys, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := producer.PrepareContext(ctx, accepted.Expectation)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				acquired := time.Now().UTC().Truncate(time.Microsecond)
				native, err := json.Marshal(map[string]any{"format": artifact.ContextFormat, "namespaceUID": accepted.Expectation.NamespaceUID, "podUID": accepted.Expectation.PodUID, "resourceVersion": "10", "observedAt": acquired, "phase": "Pending", "ready": "Unknown", "initialized": "Unknown", "scheduled": "False", "runtimeInstances": 0, "running": 0, "waiting": 0, "terminated": 0, "restarts": 0})
				if err != nil {
					t.Fatal(err)
				}
				defer clear(native)
				execution.Copies, err = prepared.StoreContext(ctx, native, execution.StartedAt, acquired)
				if err != nil {
					t.Fatal(err)
				}
				execution.Phase = "stored"
				execution.AcquiredAt = acquired
				completion, err := prepared.(evidence.StoredContextCloser).CompleteStored()
				if err != nil {
					t.Fatal(err)
				}
				execution.CompletedAt = completion.StoredAt
				currentRecovery, err := s.recovery.reader.RecoveryState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				c.Process.CheckedAt = time.Now().UTC().Truncate(time.Microsecond)
				c.Process.ValidUntil = c.Process.CheckedAt.Add(5 * time.Second)
				if _, err = execute.RecordAPIOutcome(ctx, execution, c.Process); err == nil {
					t.Fatal("generic stored result bypassed joined producer completion")
				}
				badCompletion := completion
				badCompletion.ExpectationDigest[0]++
				if _, err = execute.RecordAPIStoredCompletion(ctx, execution, badCompletion, c.Process, currentRecovery); err == nil {
					t.Fatal("foreign producer completion accepted")
				}
				execution, err = execute.RecordAPIStoredCompletion(ctx, execution, completion, c.Process, currentRecovery)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = execute.RecordAPIStoredCompletion(ctx, execution, completion, c.Process, currentRecovery); err != nil {
					t.Fatal("immutable outcome replay", err)
				}
				expiredProcess := c.Process
				expiredProcess.CheckedAt = time.Now().Add(-time.Second).UTC().Truncate(time.Microsecond)
				expiredProcess.ValidUntil = expiredProcess.CheckedAt.Add(time.Millisecond)
				if _, err = execute.RecordAPIStoredCompletion(ctx, execution, completion, expiredProcess, currentRecovery); err == nil {
					t.Fatal("outcome replay extended original process observation")
				}
				changed := execution
				changed.Copies[0].SHA256[0]++
				if _, err = execute.RecordAPIStoredCompletion(ctx, changed, completion, c.Process, currentRecovery); err == nil {
					t.Fatal("completed result rewritten")
				}
				publication := func(user, password string) *postgres.ContextPublications {
					p, e := postgres.NewContextPublications(ctx, pool(user, password), s.a.RootID, guards)
					if e != nil {
						t.Fatal(e)
					}
					return p
				}
				const compiledPassword = "synthetic-compiled-publication"
				compiledRole := narrowRole(t, ctx, admin, "api_"+strings.ReplaceAll(roleCase.purpose, "-", "_")+"_", compiledPassword, func(role string) []string {
					grants, ok := postgres.PublicRuntimeRoleGrantSQL(roleCase.purpose, role)
					if !ok {
						t.Fatal("missing compiled publication grants", roleCase.purpose)
					}
					return grants
				})
				verifyRole, verifyPassword := "context_verify_runtime", "synthetic-context-verify"
				publishRole, publishPassword := "context_publish_runtime", "synthetic-context-publish"
				if roleCase.purpose == "context-verify" {
					verifyRole, verifyPassword = compiledRole, compiledPassword
				} else {
					publishRole, publishPassword = compiledRole, compiledPassword
				}
				verify := publication(verifyRole, verifyPassword)
				audit := publication("context_verification_audit_runtime", "synthetic-context-audit")
				publish := publication(publishRole, publishPassword)
				gate, err := postgres.NewAPIContextPublicationGate(ctx, pool("api_publication_gate_runtime", "synthetic-api-publication-gate"), s.a.RootID, guards, privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, s.recovery.reader)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := objectstore.NewContextVerifier(bound, keys)
				if err != nil {
					t.Fatal(err)
				}
				p := evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: verify, ContextVerificationRecorder: verify, ContextVerificationAuditor: audit, ContextCatalogPublisher: publish}, Authority: gate, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: store, Seal: keys, Open: keys}, Now: time.Now}
				s.batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
				s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
				if err = s.p.RefreshPermissions(ctx, s.batch); err != nil {
					t.Fatal(err)
				}
				// No live target or original human request is supplied to the real gate.
				authority, err := gate.CheckContextPublication(ctx, accepted.Expectation)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = verify.RecordContextVerification(ctx, accepted.Expectation, changed.Copies, authority); err == nil {
					t.Fatal("publication accepted unrecorded copies")
				}
				var verificationRecords, catalogRecords int
				if err = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM context_verification WHERE capture_id=$1), (SELECT count(*) FROM context_catalog WHERE capture_id=$1)", accepted.CaptureID).Scan(&verificationRecords, &catalogRecords); err != nil || verificationRecords != 0 || catalogRecords != 0 {
					t.Fatal("compiled publication regression would only exercise replay", verificationRecords, catalogRecords, err)
				}
				unwraps := qualifyContextKeyUnwraps(t, ctx, admin, poolFor, s, accepted.Expectation, accepted.CaptureID)
				published, err := p.Publish(ctx, accepted.CaptureID, execution.Copies)
				if err != nil {
					t.Fatal(roleCase.purpose, "first publication with compiled grants", err)
				}
				unwraps.afterPublication(ctx, accepted.CaptureID)
				reader, err := objectstore.NewContextNativeReader(bound, keys)
				if err != nil {
					t.Fatal(err)
				}
				got, err := reader.ReadContext(ctx, published.Expectation, published.Copies, time.Now().Add(5*time.Second))
				defer clear(got)
				if err != nil || !bytes.Equal(got, native) {
					t.Fatal("native evidence changed", err)
				}
				var records int
				if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_execution WHERE root_id=$1", s.a.RootID).Scan(&records); err != nil || records != 1 {
					t.Fatal("execution identity duplicated", records, err)
				}
				qualifyPositiveContextDeletion(t, ctx, admin, poolFor, store, bound, keys, s, accepted)
			})
		}
	})
}

// contextKeyWrapFixture resolves wraps for one prepared execution's attempt.
type contextKeyWrapFixture struct {
	t       *testing.T
	wraps   *postgres.ContextKeyWraps
	peer    authorization.KeyPeer
	scope   authorization.KeyScope
	attempt string
	binding artifact.Binding
}

func (f contextKeyWrapFixture) request(role string) authorization.KeyRequestInfo {
	b, err := evidence.ArtifactKeyBinding(f.binding, role)
	if err != nil {
		f.t.Fatal(err)
	}
	return authorization.KeyRequestInfo{Scope: f.scope, AuthorityID: f.attempt, Operation: "wrap", Binding: b, RequestDigest: artifact.Digest{byte(len(role))}}
}

func (f contextKeyWrapFixture) resolve(ctx context.Context, role string) (authorization.KeyOperationPermit, error) {
	return f.wraps.Resolve(ctx, f.peer, f.request(role))
}

// qualifyContextKeyWraps checks ADR-176 on real PostgreSQL for a prepared
// execution: only the executor process's activated connector client leaf may
// wrap, each keyset role once, for exactly this attempt.
func qualifyContextKeyWraps(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, e artifact.ContextExpectation, process value.APIProcessBinding) contextKeyWrapFixture {
	connector := newConnectorSQLFixtureWithOptions(t, ctx, admin, poolFor, store, keys, s, 10800, connectorRetirementFixtureOptions{ClusterID: process.ClusterID, PodUID: process.PodUID})
	// A connector process serves only with both of its leaves activated.
	client := connector.issue(t, "client")
	connector.issue(t, "server")
	scope := authorization.KeyScope{InstallationID: s.recovery.installation, Purpose: "artifact", KeyID: "fixture"}
	// The authority runs under its own narrow login with exactly the product
	// grant list; the ledger refuses superuser or schema-creating roles.
	role := "context_key_wrap_" + strings.ReplaceAll(custodyID(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOINHERIT PASSWORD 'synthetic-key-wrap'"); err != nil {
		t.Fatal(err)
	}
	for _, grant := range postgres.ContextKeyWrapGrantSQL(role) {
		if _, err := admin.Exec(ctx, grant); err != nil {
			t.Fatal(grant, err)
		}
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		q := pgx.Identifier{role}.Sanitize()
		if _, err := admin.Exec(cleanup, "DROP OWNED BY "+q+"; DROP ROLE "+q); err != nil {
			t.Error("drop wrap role", err)
		}
	})
	wrapPool := poolFor(role, "synthetic-key-wrap")
	t.Cleanup(wrapPool.Close)
	wraps, err := postgres.NewContextKeyWraps(ctx, wrapPool, s.a.RootID, custodyID(), scope)
	if err != nil {
		t.Fatal(err)
	}
	c := client.Certificate
	f := contextKeyWrapFixture{t: t, wraps: wraps, scope: scope, attempt: e.Registration.Location.AttemptID, binding: e.Binding(),
		peer: authorization.KeyPeer{InstallationID: scope.InstallationID, PeerID: c.Binding.PeerID, Role: "collector", Certificate: c.Digest, NotBefore: c.NotBefore, NotAfter: c.NotAfter}}
	if _, err = f.resolve(ctx, "data-key"); err != nil {
		t.Fatal("executor connector leaf wrap", err)
	}
	if _, err = f.resolve(ctx, "data-key"); err == nil {
		t.Fatal("keyset role wrapped twice")
	}
	foreign := f
	foreign.peer.Certificate = artifact.Digest{0xee}
	if _, err = foreign.resolve(ctx, "index-key"); err == nil {
		t.Fatal("another certificate wrapped this attempt")
	}
	other := f
	other.attempt = custodyID()
	if _, err = other.resolve(ctx, "index-key"); err == nil {
		t.Fatal("wrap for an attempt without a prepared execution")
	}
	server := f
	server.peer.Role = "publisher"
	if _, err = server.resolve(ctx, "index-key"); err == nil {
		t.Fatal("non-collector role wrapped")
	}
	if _, err = f.resolve(ctx, "manifest-key"); err != nil {
		t.Fatal("second keyset role", err)
	}
	return f
}

type contextKeyUnwrapFixture struct {
	t       *testing.T
	unwraps *postgres.ContextKeyUnwraps
	queue   *postgres.ContextPublicationQueue
	peer    authorization.KeyPeer
	scope   authorization.KeyScope
	attempt string
	binding artifact.Binding
}

func (f contextKeyUnwrapFixture) resolve(ctx context.Context, role string, peer authorization.KeyPeer, attempt string) error {
	b, err := evidence.ArtifactKeyBinding(f.binding, role)
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.unwraps.Resolve(ctx, peer, authorization.KeyRequestInfo{Scope: f.scope, AuthorityID: attempt, Operation: "unwrap", Binding: b, RequestDigest: artifact.Digest{byte(len(role))}})
	return err
}

func (f contextKeyUnwrapFixture) queued(ctx context.Context, capture string) bool {
	pending, err := f.queue.PendingContextPublications(ctx, 64)
	if err != nil {
		f.t.Fatal("publication queue", err)
	}
	for _, p := range pending {
		if p.CaptureID == capture {
			if p.AttemptID != f.attempt || len(p.Copies) == 0 {
				f.t.Fatal("queued capture lost its attempt or copies")
			}
			return true
		}
	}
	return false
}

// narrowRole creates a NOINHERIT login with exactly the given grant list; the
// password is a fixed synthetic literal.
func narrowRole(t *testing.T, ctx context.Context, admin *pgxpool.Pool, prefix, password string, grants func(string) []string) string {
	role := prefix + strings.ReplaceAll(custodyID(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOINHERIT PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants(role) {
		if _, err := admin.Exec(ctx, grant); err != nil {
			t.Fatal(grant, err)
		}
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		q := pgx.Identifier{role}.Sanitize()
		if _, err := admin.Exec(cleanup, "DROP OWNED BY "+q+"; DROP ROLE "+q); err != nil {
			t.Error("drop narrow role", err)
		}
	})
	return role
}

// qualifyContextKeyUnwraps checks ADR-181 on real PostgreSQL for a stored,
// unpublished execution: only a verifier peer may unwrap, only this attempt's
// keyset bindings, within the bounded allowance; the queue lists the capture.
func qualifyContextKeyUnwraps(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, capture string) contextKeyUnwrapFixture {
	scope := authorization.KeyScope{InstallationID: s.recovery.installation, Purpose: "artifact", KeyID: "fixture"}
	role := narrowRole(t, ctx, admin, "context_key_unwrap_", "synthetic-key-unwrap", postgres.ContextKeyUnwrapGrantSQL)
	unwrapPool := poolFor(role, "synthetic-key-unwrap")
	t.Cleanup(unwrapPool.Close)
	unwraps, err := postgres.NewContextKeyUnwraps(ctx, unwrapPool, s.a.RootID, custodyID(), scope)
	if err != nil {
		t.Fatal(err)
	}
	queueRole := narrowRole(t, ctx, admin, "context_publication_queue_", "synthetic-publication-queue", func(r string) []string {
		grants, _ := postgres.PublicRuntimeRoleGrantSQL("context-verify", r)
		return grants
	})
	queuePool := poolFor(queueRole, "synthetic-publication-queue")
	t.Cleanup(queuePool.Close)
	queue, err := postgres.NewContextPublicationQueue(ctx, queuePool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	f := contextKeyUnwrapFixture{t: t, unwraps: unwraps, queue: queue, scope: scope, attempt: e.Registration.Location.AttemptID, binding: e.Binding(),
		peer: authorization.KeyPeer{InstallationID: scope.InstallationID, PeerID: custodyID(), Role: "verifier", Certificate: artifact.Digest{0x51}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(50 * time.Minute)}}
	if !f.queued(ctx, capture) {
		t.Fatal("stored unpublished capture missing from the publication queue")
	}
	if err = f.resolve(ctx, "data-key", f.peer, f.attempt); err != nil {
		t.Fatal("verifier unwrap of a stored attempt", err)
	}
	acquisition := f.peer
	acquisition.Role = "acquisition"
	if err = f.resolve(ctx, "index-key", acquisition, f.attempt); err == nil {
		t.Fatal("acquisition peer used the verification authority")
	}
	if err = f.resolve(ctx, "index-key", f.peer, custodyID()); err == nil {
		t.Fatal("unwrap for an attempt without a stored execution")
	}
	// A restarted verifier presents another certificate; the allowance is shared.
	other := f.peer
	other.Certificate = artifact.Digest{0x52}
	for n := 1; n < postgres.ContextKeyUnwrapAllowance; n++ {
		peer := f.peer
		if n%2 == 0 {
			peer = other
		}
		if err = f.resolve(ctx, "manifest-key", peer, f.attempt); err != nil {
			t.Fatal("verification unwrap within the allowance", n, err)
		}
	}
	if err = f.resolve(ctx, "manifest-key", f.peer, f.attempt); err == nil {
		t.Fatal("unwrap beyond the bounded allowance")
	}
	return f
}

// afterPublication: a published capture leaves the queue and gets no further
// verification unwrap; its spent allowance is never refunded.
func (f contextKeyUnwrapFixture) afterPublication(ctx context.Context, capture string) {
	if f.queued(ctx, capture) {
		f.t.Fatal("published capture remained queued")
	}
	if err := f.resolve(ctx, "data-key", f.peer, f.attempt); err == nil {
		f.t.Fatal("verification unwrap after publication")
	}
}
