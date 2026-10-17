package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identityapp "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL/S3/publication and existing current rights/retention/recovery gates.
// Process registry/routes/native protection below are explicitly synthetic
// already-accepted observations; this does not qualify installed owner discovery.
func qualifyBrowserRefreshOwners(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("browser-refresh-owner-durable-consent-and-joined-capacity", func(t *testing.T) {
		scenario, published := create(t)
		// Same SQL42 purpose grants as its separately selected qualification;
		// this case must also run when the parent selects only this subtest.
		for _, sql := range []string{
			"GRANT SELECT ON download_response,download_window,download_control_allocation TO download_runtime,download_audit_runtime,download_config_runtime",
			"GRANT INSERT ON download_response,download_window TO download_runtime",
			"GRANT UPDATE(lease_sequence,lease_until,closed) ON download_response TO download_runtime",
			"GRANT UPDATE(outcome_json) ON download_window TO download_runtime",
			"GRANT UPDATE(intent_receipt,intent_completion,outcome_receipt,outcome_completion) ON download_window TO download_audit_runtime",
			"GRANT UPDATE(id) ON download_response TO download_audit_runtime",
			"GRANT INSERT ON download_control_allocation TO download_config_runtime",
		} {
			if _, err := admin.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
		e := published.Expectation
		root := scenario.a.RootID
		role := func(name, password string) *pgxpool.Pool { p := poolFor(name, password); t.Cleanup(p.Close); return p }
		runtimePool := role("download_runtime", "synthetic-download")
		defer runtimePool.Close()
		auditPool := role("download_audit_runtime", "synthetic-download-audit")
		defer auditPool.Close()
		configPool := role("download_config_runtime", "synthetic-download-config")
		defer configPool.Close()
		catalogPool := role("context_catalog_read_runtime", "synthetic-context-read")
		defer catalogPool.Close()
		browserPool := role("browser_runtime", "synthetic-browser")
		defer browserPool.Close()
		settingsPool := role("browser_settings_runtime", "synthetic-browser-settings")
		defer settingsPool.Close()
		admissionPool := role("browser_refresh_admission_runtime", "synthetic-refresh-admission")
		defer admissionPool.Close()
		ownerPool := role("browser_refresh_owner_runtime", "synthetic-refresh-owner")
		defer ownerPool.Close()
		pausePool := role("browser_refresh_read_runtime", "synthetic-refresh-read")
		defer pausePool.Close()
		guards := postgres.EffectTransactionGuards{Retention: scenario.retention.guard, Recovery: scenario.recovery.guard}
		downloads, err := postgres.NewDownloads(ctx, runtimePool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := postgres.NewDownloads(ctx, auditPool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		config, err := postgres.NewDownloads(ctx, configPool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := postgres.NewContextPublications(ctx, catalogPool, root, guards)
		if err != nil {
			t.Fatal(err)
		}
		gate := authorizationapp.ContextDownloadAuthority{RootID: root, Permissions: scenario.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: scenario.retention, Now: time.Now}, Environment: newDownloadTestEnvironment(t, ctx, catalogPool, scenario, e.Registration), Now: time.Now}
		scope := artifact.DownloadScope{RootID: root, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: scenario.a.Plan.Input.Executor}
		bRoot, bEpoch := custodyID(), custodyID()
		settings := identity.BrowserSettings{RootID: bRoot, Epoch: bEpoch, Issuer: scope.Principal.Issuer, ClientID: scope.Principal.ClientID, Origin: "https://console.invalid", Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: [32]byte{1}}, MaxLifetimeSeconds: 3600, MaxLogins: 4, MaxSessions: 1, MaxLogoutEvents: 4}
		projection, err := postgres.NewBrowserSettingsProjection(ctx, settingsPool, bRoot)
		if err != nil {
			t.Fatal(err)
		}
		current := func() (identityapp.CurrentIdentity, artifact.DownloadAuthority) {
			t.Helper()
			n := time.Now().UTC().Truncate(time.Microsecond)
			settings.ObservedAt = n
			settings.FreshUntil = n.Add(5 * time.Second)
			if err := projection.ObserveBrowserSettings(ctx, settings); err != nil {
				t.Fatal(err)
			}
			batch := scenario.batch
			batch.Initial = nil
			batch.ObservedAt = n
			batch.FreshUntil = n.Add(5 * time.Second)
			if err := scenario.p.RefreshPermissions(ctx, batch); err != nil {
				t.Fatal(err)
			}
			actor := scenario.a.Eligibility.VerifiedIdentity
			actor.Scopes = []string{"evidence:read", "evidence:download"}
			actor.VerifiedAt = n
			actor.ValidUntil = n.Add(5 * time.Second)
			c, _, err := identityapp.NewBearerRequest(ctx, downloadTestIdentity{actor}, "synthetic-reference", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			a, err := gate.CheckDownloadCurrent(ctx, c, scope)
			if err != nil {
				t.Fatal(err)
			}
			return c, a
		}
		c, a := current()
		allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 16 << 20, SessionLimit: 3, ValidUntil: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)}
		if err = config.BindDownloadAllocation(ctx, allocation); err != nil {
			t.Fatal(err)
		}
		control := artifact.DownloadControlAllocation{ID: allocation.ID, RootID: root, AuditStoreID: e.Registration.StoreID, ResponseLimit: 2, WindowLimit: 2, AuditByteLimit: 4 * artifact.DownloadWindowAuditBytes, ValidUntil: allocation.ValidUntil, AuditWriteUntil: allocation.ValidUntil.Add(time.Minute)}
		if err = config.BindDownloadControlAllocation(ctx, control); err != nil {
			t.Fatal("response backing", err)
		}
		reservation := evidence.DownloadReservation{Authority: a, IdempotencyDigest: artifact.Digest{81}, Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: artifact.Digest{82}, State: artifact.DownloadPreparing, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(40 * time.Second), OutputLimit: 65536, ReadLimit: 8 << 20, RequestLimit: 4}}
		download, err := downloads.ReserveDownload(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := store.ForCustody(e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		native, err := objectstore.NewContextNativeReader(bound, keys)
		if err != nil {
			t.Fatal(err)
		}
		worker := evidence.ContextDownloadWorker{Sessions: downloads, AuditAcknowledgements: ack, Audit: &objectstore.DownloadAuditObjects{Store: store, Seal: keys, Open: keys}, CurrentAuthority: gate, Native: native, Now: time.Now, NewID: custodyID}
		c, _ = current()
		metadata, err := worker.PrepareCurrent(ctx, c, evidence.ContextDownloadRequest{SessionID: download.ID, Scope: scope, Expectation: e, Copies: published.Copies})
		if err != nil {
			t.Fatal("actual native preparation", err)
		}
		sessionDB := func(pool *pgxpool.Pool) *postgres.BrowserSessions {
			v, err := postgres.NewBrowserSessions(ctx, pool, settings.Binding())
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		sessions := sessionDB(browserPool)
		n := time.Now().UTC().Truncate(time.Microsecond)
		record := identity.BrowserSession{ID: sha256.Sum256([]byte(custodyID())), Principal: scope.Principal, ProviderSession: "synthetic-refresh-session", Ciphertext: []byte("synthetic-ciphertext"), CreatedAt: n, AuthenticatedAt: n, ExpiresAt: n.Add(time.Minute), RefreshAt: n.Add(time.Second), Version: 1}
		if _, err = sessions.CreateSession(ctx, record); err != nil {
			t.Fatal(err)
		}
		serving, auth, process := refreshOwnerProcessFixture(scenario.recovery.installation, scope.ClusterID, bRoot, bEpoch)
		owners, err := postgres.NewBrowserRefreshOwners(postgres.BrowserRefreshDatabases{Admission: sessionDB(admissionPool), Maintenance: sessionDB(ownerPool), Reader: sessionDB(pausePool)}, downloads, gate, serving, auth, process, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		pin := identity.RefreshSessionPin{ID: record.ID, Principal: record.Principal, ProviderSession: record.ProviderSession, CreatedAt: record.CreatedAt, AuthenticatedAt: record.AuthenticatedAt, ExpiresAt: record.ExpiresAt}
		proposal := identity.RefreshOwnerRef{RootID: bRoot, Epoch: bEpoch, OwnerID: custodyID(), InstallationID: process.InstallationID, ClusterID: process.ClusterID, PodUID: process.PodUID, ProcessEpoch: process.ProcessEpoch, SessionID: record.ID, Generation: 1}
		c, _ = current()
		admitted, err := owners.AdmitBrowserRefresh(ctx, c, pin, proposal, download.ID)
		if err != nil {
			t.Fatal("POST consent", err)
		}
		// Lost admission reply replay returns the existing same-process owner and
		// fixed consumer dates, without additional capacity or a fresh grace period.
		var first, grace time.Time
		if err = admin.QueryRow(ctx, "SELECT first_admitted_at,grace_until FROM browser_refresh_consumer WHERE download_id=$1", download.ID).Scan(&first, &grace); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		answers := make(chan error, 4)
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				p := proposal
				p.OwnerID = custodyID()
				got, e := owners.AdmitBrowserRefresh(ctx, c, pin, p, download.ID)
				if e == nil && got.Owner != admitted.Owner {
					e = errors.New("replay replaced original owner")
				}
				answers <- e
			}()
		}
		wg.Wait()
		close(answers)
		for err = range answers {
			if err != nil {
				t.Fatal("same-process replay", err)
			}
		}
		var afterFirst, afterGrace time.Time
		if err = admin.QueryRow(ctx, "SELECT first_admitted_at,grace_until FROM browser_refresh_consumer WHERE download_id=$1", download.ID).Scan(&afterFirst, &afterGrace); err != nil || !first.Equal(afterFirst) || !grace.Equal(afterGrace) {
			t.Fatal("replay renewed attachment", err)
		}
		unrelated := proposal
		unrelated.OwnerID = custodyID()
		if err = owners.AbandonBrowserRefreshAdmission(ctx, unrelated); err != nil {
			t.Fatal("different proposal cleanup", err)
		}
		var originalStillOpen bool
		if err = admin.QueryRow(ctx, "SELECT joined_at IS NULL FROM browser_refresh_owner WHERE owner_id=$1", admitted.Owner.OwnerID).Scan(&originalStillOpen); err != nil || !originalStillOpen {
			t.Fatal("different proposed owner closed actual work", err)
		}
		if err = sessions.ClaimRefresh(ctx, record.ID, 1, [32]byte{1}); !errors.Is(err, identity.ErrSessionBusy) {
			t.Fatal("ordinary POST competed with current owner", err)
		}
		c, a = current()
		response, err := downloads.BeginDownloadResponse(ctx, download.ID, a, artifact.DownloadResponse{ID: custodyID(), SessionID: download.ID, OwnerID: custodyID(), Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: metadata.Size}, WholeFile: true, WindowReadLimit: evidence.ContextDownloadReadWork}, Until: download.Deadline})
		if err != nil {
			t.Fatal("actual response lease", err)
		}
		responseBinding := identity.RefreshResponseBinding{DownloadID: download.ID, ResponseID: response.ID, ResponseOwnerID: response.OwnerID, ResponseGeneration: response.Generation}
		demand, err := owners.ObserveBrowserRefresh(ctx, admitted.Owner)
		if err != nil {
			t.Fatal("current backed demand", err)
		}
		c, _ = current()
		if _, err = sessionDB(ownerPool).ReadSession(ctx, record.ID); err != nil {
			t.Fatal("owner role current session before claim", err)
		}
		if _, err = downloads.LookupDownload(ctx, download.ID, record.Principal); err != nil {
			t.Fatal("current response session before owned claim", err)
		}
		if _, err = gate.CheckDownloadCurrent(ctx, c, scope); err != nil {
			t.Fatal("current download authority before owned claim", err)
		}
		claim := [32]byte{2}
		if err = owners.ClaimBrowserOwnedRefresh(ctx, c, demand, 1, claim); err != nil {
			t.Fatal("one-use owned claim", err)
		}
		if err = owners.ClaimBrowserOwnedRefresh(ctx, c, demand, 1, [32]byte{3}); err == nil {
			t.Fatal("owned claim replayed")
		}
		pause, err := owners.BrowserRefreshPause(ctx, record.ID, record.Principal, responseBinding)
		if err != nil || pause.Settled || !pause.Matches(responseBinding) || pause.CredentialVersion != 1 {
			t.Fatal("exact pending no-output pause", err)
		}
		wrong := responseBinding
		wrong.ResponseOwnerID = custodyID()
		if _, err = owners.BrowserRefreshPause(ctx, record.ID, record.Principal, wrong); err == nil {
			t.Fatal("foreign response obtained refresh pause")
		}
		if err = sessions.FinishRefresh(ctx, record.ID, 1, claim, []byte("synthetic-committed-token-replacement"), time.Now().Add(time.Second)); err != nil {
			t.Fatal("committed replacement", err)
		}
		if _, err = owners.BrowserRefreshPause(ctx, record.ID, record.Principal, responseBinding); err == nil {
			t.Fatal("unjoined provider result declared settled")
		}
		if err = owners.JoinBrowserRefreshClaim(ctx, admitted.Owner, 1, claim); err != nil {
			t.Fatal(err)
		}
		settled, err := owners.BrowserRefreshPause(ctx, record.ID, record.Principal, responseBinding)
		if err != nil || !settled.Settled || settled.CredentialVersion != 1 || !settled.ClaimUntil.Equal(pause.ClaimUntil) {
			t.Fatal("completion between Busy and lookup lost original wakeup", err)
		}
		// A second actual one-use claim provides blocked work for the logout
		// test. Settled granted no refresh, new claim or byte lease itself.
		c, _ = current()
		demand, err = owners.ObserveBrowserRefresh(ctx, admitted.Owner)
		if err != nil {
			t.Fatal(err)
		}
		claim = [32]byte{4}
		if err = owners.ClaimBrowserOwnedRefresh(ctx, c, demand, 2, claim); err != nil {
			t.Fatal("second current owned claim", err)
		}
		if err = owners.CloseBrowserRefreshOwner(ctx, admitted.Owner); err == nil {
			t.Fatal("unjoined provider work refunded")
		}
		if err = owners.AbandonBrowserRefreshAdmission(ctx, proposal); err == nil {
			t.Fatal("unstarted cleanup adopted a claimed owner")
		}
		// Logout removes identity immediately. Retained owner capacity survives the
		// session DELETE and prevents repeated login/logout from multiplying work.
		if err = sessions.RevokeSession(ctx, record.ID); err != nil {
			t.Fatal(err)
		}
		next := record
		next.ID = sha256.Sum256([]byte(custodyID()))
		next.ProviderSession = "next-session"
		if _, err = sessions.CreateSession(ctx, next); !errors.Is(err, identity.ErrSessionCapacity) {
			t.Fatal("logout refunded unjoined global owner", err)
		}
		if err = sessions.FinishRefresh(ctx, record.ID, 2, claim, []byte("late-provider-result"), time.Now().Add(time.Second)); err == nil {
			t.Fatal("logout lost to owned refresh result")
		}
		if _, err = owners.ObserveBrowserRefresh(ctx, admitted.Owner); err == nil {
			t.Fatal("deleted browser session retained demand")
		}
		if err = owners.JoinBrowserRefreshClaim(ctx, admitted.Owner, 2, claim); err != nil {
			t.Fatal("actual joined claim", err)
		}
		if err = owners.CloseBrowserRefreshOwner(ctx, admitted.Owner); err != nil {
			t.Fatal("joined closure", err)
		}
		if _, err = sessions.CreateSession(ctx, next); err != nil {
			t.Fatal("positive joined capacity not returned", err)
		}
		var detached bool
		if err = admin.QueryRow(ctx, "SELECT owner_id IS NULL AND first_admitted_at=$2 AND grace_until=$3 FROM browser_refresh_consumer WHERE download_id=$1", download.ID, first, grace).Scan(&detached); err != nil || !detached {
			t.Fatal("consumer history lost immutable grace", err)
		}
		// Model an already-sent admission transaction whose COMMIT settles only
		// after its caller has returned. The exact same admission role/guard and
		// root lock are used; no synthetic timeout is treated as transaction join.
		_, _ = current()
		delayed := proposal
		delayed.SessionID, delayed.OwnerID = next.ID, custodyID()
		tx, err := admissionPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		var blocker int32
		if err = tx.QueryRow(ctx, "SELECT pg_backend_pid() FROM browser_session_root WHERE id=$1 FOR UPDATE", bRoot).Scan(&blocker); err != nil {
			t.Fatal(err)
		}
		providerKey := sha256.Sum256([]byte(next.ProviderSession))
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		if _, err = tx.Exec(ctx, `INSERT INTO browser_refresh_owner(root_id,session_id,epoch,owner_id,generation,installation_id,cluster_id,pod_uid,process_epoch,actor_key,provider_session_key,session_created_at,authenticated_at,session_expires_at,started_at,lease_until)
SELECT s.root_id,s.id,s.epoch,$3,1,$4,$5,$6,$7,d.actor_key,$8,s.created_at,s.authenticated_at,s.expires_at,$9,$10
FROM browser_session s JOIN artifact_download d ON d.id=$11 WHERE s.root_id=$1 AND s.id=$2`, bRoot, next.ID[:], delayed.OwnerID, process.InstallationID, process.ClusterID, process.PodUID, process.ProcessEpoch, providerKey[:], stamp, stamp.Add(15*time.Second), download.ID); err != nil {
			t.Fatal("delayed actual admission insert", err)
		}
		cleaned := make(chan error, 1)
		go func() { cleaned <- owners.AbandonBrowserRefreshAdmission(ctx, delayed) }()
		observed := false
		waitEnd := time.Now().Add(time.Second)
		for !observed {
			select {
			case err = <-cleaned:
				t.Fatal("cleanup reported absence before admission transaction settled", err)
			default:
			}
			if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='browser_refresh_owner_runtime' AND $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if !observed {
				if !time.Now().Before(waitEnd) {
					t.Fatal("cleanup never reached original admission lock")
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-cleaned; err != nil {
			t.Fatal("joined late admission cleanup", err)
		}
		var positivelyClosed bool
		if err = admin.QueryRow(ctx, "SELECT joined_at IS NOT NULL AND claim IS NULL FROM browser_refresh_owner WHERE owner_id=$1", delayed.OwnerID).Scan(&positivelyClosed); err != nil || !positivelyClosed {
			t.Fatal("delayed commit escaped exact unstarted cleanup", err)
		}
		// Purpose credentials cannot introduce a second owner or acquire bytes.
		for _, p := range []*pgxpool.Pool{ownerPool, pausePool} {
			if _, err = p.Exec(ctx, "INSERT INTO browser_refresh_owner SELECT * FROM browser_refresh_owner LIMIT 0"); err == nil {
				t.Fatal("non-admission role can create owners")
			}
			if _, err = p.Exec(ctx, "UPDATE artifact_download SET charged_output=charged_output+1 WHERE id=$1", download.ID); err == nil {
				t.Fatal("refresh role can spend evidence output")
			}
		}
		for _, statement := range []string{
			"UPDATE browser_session SET id=id WHERE false",
			"UPDATE browser_session SET refresh_claim=NULL WHERE false",
			"DELETE FROM browser_session WHERE false",
		} {
			_, err = pausePool.Exec(ctx, statement)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "42501" {
				t.Fatal("pause role mutation must fail the privilege check", err)
			}
		}
		if _, err = browserPool.Exec(ctx, "SELECT * FROM context_catalog LIMIT 1"); err == nil {
			t.Fatal("ordinary browser received evidence SQL privilege")
		}
		t.Log("actual SQL publication-backed owner replay, exact pending/settled response pause, one-use claims, delayed admission closure, logout/retained capacity and joined close; process authority is explicitly synthetic; no external provider or byte transfer in this case")
	})
}

type refreshProcessFixture struct {
	certificate   fleet.OwnerCertificate
	enrollment    fleet.OwnerEnrollment
	configuration fleet.OwnerConfiguration
}

func (f refreshProcessFixture) ServingCertificate() (fleet.OwnerCertificate, error) {
	return f.certificate, nil
}
func (f refreshProcessFixture) VerifyServingCertificate(fleet.OwnerConfigurationObservation) (fleet.OwnerCertificate, error) {
	return f.certificate, nil
}
func (f refreshProcessFixture) observation() fleet.OwnerConfigurationObservation {
	n := time.Now()
	return fleet.OwnerConfigurationObservation{Configuration: f.configuration.Clone(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
}
func (f refreshProcessFixture) ReadOwnerRegistration(context.Context, fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
	n := time.Now()
	return fleet.OwnerRegistrationObservation{Enrollment: f.enrollment, Certificate: f.certificate, Configuration: f.observation(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}
func (f refreshProcessFixture) CurrentOwnerRoute(context.Context, fleet.OwnerBinding) (fleet.OwnerRoute, error) {
	n := time.Now()
	return fleet.OwnerRoute{Configuration: f.observation(), Endpoint: fleet.OwnerEndpoint{Binding: f.certificate.Binding, Pool: f.configuration.Pool, Pod: f.enrollment.Pod, ReplicaSetUID: f.enrollment.ReplicaSetUID, Addresses: []string{"10.0.1.2"}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}
func (f refreshProcessFixture) ReadOwnerProtection(context.Context, fleet.OwnerPool) (fleet.OwnerProtection, error) {
	n := time.Now()
	return fleet.OwnerProtection{Pool: f.configuration.Pool, Digest: artifact.Digest{7}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}
func refreshOwnerProcessFixture(installation, cluster, root, epoch string) (refreshProcessFixture, *fleetapp.OwnerAuthenticator, identity.RefreshProcessBinding) {
	n := time.Now()
	id := custodyID()
	p := fleet.OwnerPool{InstallationID: installation, ClusterID: cluster, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}
	b := fleet.OwnerBinding{InstallationID: installation, ClusterID: cluster, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	_, hold, _ := fleet.OwnerCertificateWindow(n.Add(-time.Second))
	f := refreshProcessFixture{certificate: fleet.OwnerCertificate{Binding: b, Usage: "server", Digest: artifact.Digest{1}, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(10 * time.Minute)}, enrollment: fleet.OwnerEnrollment{ID: id, Binding: b, Usage: "server", Pool: p, SourceUID: id, Pod: "hub-pod", ReplicaSet: "hub-rs", ReplicaSetUID: id, PublicKeyDigest: artifact.Digest{2}, InitialTokenDigest: artifact.Digest{3}, InitialWorkloadDigest: artifact.Digest{4}, InitialProtectionDigest: artifact.Digest{5}, ClaimedAt: n.Add(-time.Second), InitialHoldUntil: hold.Add(time.Minute)}, configuration: fleet.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{6}}, ProtectionDigest: artifact.Digest{7}, IssuerRoots: [][]byte{{8}}}}
	return f, &fleetapp.OwnerAuthenticator{Registry: f, Routes: f, Protection: f, Now: time.Now}, identity.RefreshProcessBinding{RootID: root, Epoch: epoch, InstallationID: installation, ClusterID: cluster, PodUID: id, ProcessEpoch: id}
}
