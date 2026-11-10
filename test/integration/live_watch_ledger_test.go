package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	live "asservat.local/asservat/internal/domain/live"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real compiled hub SQL duty and actual audited owner registry. Initial fleet,
// native Pod proof, permission root and private CA are synthetic fixture inputs.
// No C3 source dispatch, wire delivery or installed runtime is qualified here.
func TestLiveWatchLedgerWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_FLEET_FIXTURES")
	}
	if path == "" {
		t.Skip("owned SQL/S3 fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ca, key := connectorSQLCA(t)
	ownerPool := fleet.OwnerPool{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), Namespace: "hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443, NativePort: 8444}
	config := fleet.OwnerConfiguration{Pool: ownerPool, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{ca.Raw}}
	lab := ownerConfigurationLab(t, ctx, f, config)
	owners := newContextStartOwnerSQL(t, ctx, lab, config, contextStartOwnerIssuer{ca, key})
	if _, err = owners.refresh(ctx, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	request := fleet.OwnerEnrollmentRequest{Binding: fleet.OwnerBinding{InstallationID: ownerPool.InstallationID, ClusterID: ownerPool.ClusterID, IssuerEpoch: ownerPool.IssuerEpoch, PodUID: custodyID(), ProcessEpoch: custodyID()}, Usage: "server", CSRDER: connectorSQLCSR(t)}
	issued, err := owners.coordinator().Enroll(ctx, request)
	if err != nil {
		t.Fatal("actual audited owner activation", err)
	}
	certificateReads := 0
	current := func(c context.Context) (fleet.OwnerCertificate, error) {
		certificateReads++
		if _, err := owners.refresh(c, 5*time.Second); err != nil {
			return fleet.OwnerCertificate{}, err
		}
		return issued.Certificate, nil
	}
	root := custodyID()
	seedRoot := func(root string) {
		t.Helper()
		if _, err := lab.admin.Exec(ctx, `INSERT INTO permission_stream(id,epoch,trust_digest,lease_until) VALUES($1,$2,$3,clock_timestamp()+interval '1 minute')`, root, custodyID(), bytes.Repeat([]byte{1}, 32)); err != nil {
			t.Fatal("synthetic protected permission root", err)
		}
	}
	seedRoot(root)
	role := narrowRole(t, ctx, lab.admin, "live_hub_", "synthetic-live-hub", func(name string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", name)
		if !ok {
			t.Fatal("compiled hub role")
		}
		return grants
	})
	pc := lab.writerPool.Config()
	pc.ConnConfig.User = role
	pc.ConnConfig.Password = "synthetic-live-hub"
	pc.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	limits := postgres.LiveWatchLimits{InstallationSlots: 2, PrincipalSlots: 1, WorkloadSlots: 2, MemoryBytes: 2 << 20, InstallationRate: 1, InstallationBurst: 1 << 20, PrincipalRate: 1, PrincipalBurst: 48 << 10, WorkloadRate: 1, WorkloadBurst: 48 << 10, WatchBurst: 24 << 10, MaxOutputBytes: 1 << 20, MaxRate: 64 << 10, MaxDurationSeconds: 60, MaxAccounts: 16, MaxControlRecords: 128}
	workloadLimits := limits
	workloadLimits.InstallationSlots = 3
	workloadLimits.PrincipalSlots = 3
	workloadLimits.MemoryBytes = 3 << 20
	ledger, err := postgres.NewLiveWatches(ctx, pool, root, request.Binding.ProcessEpoch, owners.reader, current, workloadLimits)
	if err != nil {
		t.Fatal("compiled hub live constructor", err)
	}
	var tableRead bool
	if err = lab.admin.QueryRow(ctx, `SELECT has_table_privilege($1,'live_watch_control','SELECT')`, role).Scan(&tableRead); err != nil || tableRead {
		t.Fatal("live control table exposed", err)
	}
	if certificateReads != 0 {
		t.Fatal("constructor required credentials before runtime enrollment")
	}
	makeControl := func(p, w byte) liveapp.Control {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return liveapp.Control{ID: custodyID(), OwnerID: request.Binding.ProcessEpoch, Fence: custodyID(), PrincipalKey: [32]byte{p}, WorkloadKey: [32]byte{w}, RequestDigest: [32]byte{3}, Revision: 1, State: "Active", AcceptedAt: now, ExpiresAt: now.Add(8 * time.Second), IdleUntil: now.Add(8 * time.Second), OutputLimit: 1 << 20, BytesPerSecond: 1}
	}
	keyFor := func(v byte) string { return hex.EncodeToString(bytes.Repeat([]byte{v}, 32)) }
	firstWorkload := makeControl(4, 7)
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, firstWorkload, keyFor(10)); err != nil {
		t.Fatal("first workload control", err)
	}
	secondWorkload := makeControl(5, 7)
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, secondWorkload, keyFor(11)); err != nil {
		t.Fatal("second workload control", err)
	}
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, makeControl(6, 7), keyFor(12)); !errors.Is(err, live.ErrCapacity) {
		t.Fatal("third principal bypassed the workload ceiling below installation/principal limits", err)
	}
	outsideWorkload := makeControl(6, 8)
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, outsideWorkload, keyFor(13)); err != nil {
		t.Fatal("workload refusal blocked an unrelated workload", err)
	}
	closeWorkload := func(control liveapp.Control) {
		t.Helper()
		control.State = "Closed"
		control.Revision++
		if _, err = ledger.Change(ctx, control, control.Revision-1, 0); err != nil {
			t.Fatal("workload control close", err)
		}
	}
	closeWorkload(firstWorkload)
	releasedWorkload := makeControl(6, 7)
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, releasedWorkload, keyFor(14)); err != nil {
		t.Fatal("workload close did not release its slot", err)
	}
	closeWorkload(secondWorkload)
	closeWorkload(outsideWorkload)
	closeWorkload(releasedWorkload)
	workloadTimer := time.NewTimer(time.Until(releasedWorkload.ExpiresAt) + time.Millisecond)
	defer workloadTimer.Stop()
	select {
	case <-workloadTimer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	workloadControls, workloadAccounts, err := ledger.PruneExpired(ctx)
	if err != nil || workloadControls != 4 || workloadAccounts != 6 {
		t.Fatal("closed unspent workload fixture did not prune", workloadControls, workloadAccounts, err)
	}
	ledger, err = postgres.NewLiveWatches(ctx, pool, root, request.Binding.ProcessEpoch, owners.reader, current, limits)
	if err != nil {
		t.Fatal("restore original live limits", err)
	}
	c := makeControl(1, 2)
	got, reused, err := ledger.Create(ctx, ownerPool.ClusterID, c, keyFor(1))
	if err != nil || reused || got != c {
		t.Fatal("original control", err, reused)
	}
	viewers, err := postgres.NewLiveViewerCapacity(ctx, pool, ownerPool.InstallationID)
	if err != nil {
		t.Fatal("compiled viewer capacity constructor", err)
	}
	clusterKey := sha256.Sum256([]byte("asservat-live-cluster/v1\x00" + ownerPool.ClusterID))
	active, fresh, err := viewers.ReadLiveViewers(ctx, ownerPool.InstallationID, ownerPool.ClusterID)
	if err != nil || active != 1 || !fresh.After(time.Now()) {
		t.Fatal("active viewer aggregate", active, fresh, err)
	}
	otherCluster, _, err := viewers.ReadLiveViewers(ctx, ownerPool.InstallationID, custodyID())
	if err != nil || otherCluster != 0 {
		t.Fatal("viewer aggregate leaked across clusters", otherCluster, err)
	}
	assertOwner := func(watch, key string) {
		t.Helper()
		before := certificateReads
		binding, found, err := ledger.LookupLiveWatchOwner(ctx, c.PrincipalKey, watch, key)
		if err != nil || !found || binding != request.Binding || certificateReads != before {
			t.Fatal("exact original owner locator without provider calls", found, err)
		}
	}
	assertOwner(c.ID, "")
	assertOwner("", keyFor(1))
	// Restrictive retirement is injected in one rolled-back administrator
	// transaction; the actual locator itself runs under the compiled hub role.
	// No owner/certificate replacement or production registry mutation remains.
	tx, err := lab.admin.Begin(ctx)
	if err != nil {
		t.Fatal("owner retirement control", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(ctx, `UPDATE hub_owner_enrollment SET retired_at=clock_timestamp() WHERE installation_id=$1 AND process_epoch=$2 AND usage='server'`, ownerPool.InstallationID, request.Binding.ProcessEpoch); err != nil {
		t.Fatal("retirement negative input", err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal("compiled role retirement control", err)
	}
	var retiredViewers int
	if err = tx.QueryRow(ctx, `SELECT live_watch_viewers($1,$2)`, ownerPool.InstallationID, clusterKey[:]).Scan(&retiredViewers); err != nil || retiredViewers != 0 {
		t.Fatal("retired owner remained an active viewer", retiredViewers, err)
	}
	var ignored string
	err = tx.QueryRow(ctx, `SELECT installation_id::text FROM live_watch_owner($1,$2,$3,NULL)`, root, c.PrincipalKey[:], c.ID).Scan(&ignored)
	var unavailable *pgconn.PgError
	if !errors.As(err, &unavailable) || unavailable.Code != "55000" {
		t.Fatal("retired owner became absent or routable", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal("retirement control rollback", err)
	}
	assertOwner(c.ID, "")
	for _, absent := range []struct {
		principal  [32]byte
		watch, key string
	}{{[32]byte{9}, c.ID, ""}, {c.PrincipalKey, custodyID(), ""}, {c.PrincipalKey, "", keyFor(9)}} {
		binding, found, err := ledger.LookupLiveWatchOwner(ctx, absent.principal, absent.watch, absent.key)
		if err != nil || found || binding != (fleet.OwnerBinding{}) {
			t.Fatal("unrelated principal/watch/client-key located owner", found, err)
		}
	}
	root2 := custodyID()
	seedRoot(root2)
	secondRoot, err := postgres.NewLiveWatches(ctx, pool, root2, request.Binding.ProcessEpoch, owners.reader, current, limits)
	if err != nil {
		t.Fatal("second-root adapter construction", err)
	}
	if _, _, err = secondRoot.Create(ctx, ownerPool.ClusterID, makeControl(9, 9), keyFor(9)); err == nil {
		t.Fatal("second root minted installation aggregate pool")
	}

	retry := makeControl(1, 2)
	got, reused, err = ledger.Create(ctx, ownerPool.ClusterID, retry, keyFor(1))
	if err != nil || !reused || got != c {
		t.Fatal("key replay renewed control", err, reused)
	}
	retry.RequestDigest = [32]byte{9}
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, retry, keyFor(1)); !errors.Is(err, live.ErrConflict) {
		t.Fatal("changed selection replay", err)
	}
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, makeControl(1, 2), keyFor(2)); !errors.Is(err, live.ErrCapacity) {
		t.Fatal("principal concurrent slot bypass", err)
	}
	if err = ledger.CurrentLive(ctx, c); err != nil {
		t.Fatal("exact current control", err)
	}
	bad := c
	bad.Fence = custodyID()
	if err = ledger.CurrentLive(ctx, bad); !errors.Is(err, live.ErrDenied) || errors.Is(err, live.ErrUnavailable) {
		t.Fatal("changed fence must be a refusal, not an outage", err)
	}
	c.Spent += 24 << 10
	c, err = ledger.Change(ctx, c, c.Revision, 24<<10)
	if err != nil {
		t.Fatal("first paid batch", err)
	}
	snapshot := func() (int64, int64) {
		t.Helper()
		var rows, spent int64
		if err := lab.admin.QueryRow(ctx, `SELECT count(*),sum((CASE kind WHEN 'installation' THEN $2::bigint WHEN 'principal' THEN $3::bigint ELSE $3::bigint END)::bigint*1000000-tokens_micro) FROM live_watch_account WHERE root_id=$1`, root, int64(1<<20), int64(48<<10)).Scan(&rows, &spent); err != nil {
			t.Fatal(err)
		}
		return rows, spent
	}
	rows, spent := snapshot()
	if rows != 3 || spent != 3*(24<<10)*1000000 {
		t.Fatal("three ancestor accounts charged exactly once", rows, spent)
	}
	tooMuch := c
	tooMuch.Spent += 24 << 10
	if _, err = ledger.Change(ctx, tooMuch, c.Revision, 24<<10); !errors.Is(err, live.ErrCapacity) {
		t.Fatal("per-watch rate not enforced", err)
	}
	if r, s := snapshot(); r != rows || s != spent {
		t.Fatal("failed debit changed ancestor accounts", r, s)
	}
	other := makeControl(2, 3)
	other, _, err = ledger.Create(ctx, ownerPool.ClusterID, other, keyFor(4))
	if err != nil {
		t.Fatal("second distinct principal consumes installation slot", err)
	}
	if _, _, err = ledger.Create(ctx, ownerPool.ClusterID, makeControl(3, 4), keyFor(5)); !errors.Is(err, live.ErrCapacity) {
		t.Fatal("third distinct principal bypassed installation ceiling", err)
	}
	other.State = "Closed"
	other.Revision++
	if other, err = ledger.Change(ctx, other, other.Revision-1, 0); err != nil {
		t.Fatal("release installation slot", err)
	}
	c.State = "Closed"
	c.Revision++
	c, err = ledger.Change(ctx, c, c.Revision-1, 0)
	if err != nil {
		t.Fatal("restrictive close", err)
	}
	if err = ledger.CurrentLive(ctx, c); err != nil {
		t.Fatal("exact closed receipt current", err)
	}
	active, _, err = viewers.ReadLiveViewers(ctx, ownerPool.InstallationID, ownerPool.ClusterID)
	if err != nil || active != 0 {
		t.Fatal("closed viewers remained active", active, err)
	}
	assertOwner(c.ID, "")
	assertOwner("", keyFor(1))
	terminalPaid := c
	terminalPaid.Spent++
	if _, err = ledger.Change(ctx, terminalPaid, c.Revision, 1); err == nil {
		t.Fatal("terminal positive cost")
	}
	second := makeControl(1, 2)
	second, _, err = ledger.Create(ctx, ownerPool.ClusterID, second, keyFor(2))
	if err != nil {
		t.Fatal("closed slot not released", err)
	}
	second.Spent += 24 << 10
	second, err = ledger.Change(ctx, second, 1, 24<<10)
	if err != nil {
		t.Fatal("second actual watch debit", err)
	}
	second.State = "Closed"
	second.Revision++
	second, err = ledger.Change(ctx, second, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	third := makeControl(1, 2)
	third, _, err = ledger.Create(ctx, ownerPool.ClusterID, third, keyFor(3))
	if err != nil {
		t.Fatal(err)
	}
	third.Spent += 24 << 10
	if _, err = ledger.Change(ctx, third, 1, 24<<10); !errors.Is(err, live.ErrCapacity) {
		t.Fatal("close/reopen reset shared ancestor debt", err)
	}
	third.Spent -= 24 << 10
	recovered, err := ledger.ReadLiveControl(ctx, third.PrincipalKey, third.ID)
	if err != nil || recovered != third {
		t.Fatal("exact minimized recovery control", recovered, err)
	}
	if _, err = ledger.ReadLiveControl(ctx, [32]byte{9}, third.ID); !errors.Is(err, live.ErrUnavailable) {
		t.Fatal("foreign principal read recovery control", err)
	}
	wrongFence := third
	wrongFence.Fence = custodyID()
	if _, err = ledger.CloseLiveControl(ctx, wrongFence); !errors.Is(err, live.ErrConflict) {
		t.Fatal("recovery closed a changed fence", err)
	}
	third, err = ledger.CloseLiveControl(ctx, third)
	if err != nil || third.State != "Closed" || third.Revision != recovered.Revision || !third.ExpiresAt.Equal(recovered.ExpiresAt) || !third.IdleUntil.Equal(recovered.IdleUntil) || third.Spent != recovered.Spent {
		t.Fatal("recovery close changed original control bounds", third, recovered, err)
	}
	replayed, err := ledger.CloseLiveControl(ctx, third)
	if err != nil || replayed != third {
		t.Fatal("recovery close was not idempotent", replayed, err)
	}
	changed := limits
	changed.PrincipalBurst++
	replacement, err := postgres.NewLiveWatches(ctx, pool, root, request.Binding.ProcessEpoch, owners.reader, current, changed)
	if err != nil {
		t.Fatal("configuration-only constructor", err)
	}
	if _, _, err = replacement.Create(ctx, ownerPool.ClusterID, makeControl(8, 8), keyFor(8)); err == nil {
		t.Fatal("live limits replacement reset debt")
	}
	if _, err = ledger.Change(ctx, liveapp.Control{}, 1, 0); err == nil {
		t.Fatal("missing control")
	}
	// Wait only for the immutable original ends. Neither prune nor a new owner
	// observation renews them, and outstanding ancestor debt survives removal.
	timer := time.NewTimer(time.Until(third.ExpiresAt) + time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err = ledger.Change(ctx, third, 1, 24<<10); err == nil {
		t.Fatal("paid read after original hard end")
	}
	if _, found, err := ledger.LookupLiveWatchOwner(ctx, third.PrincipalKey, "", keyFor(3)); err == nil || found {
		t.Fatal("expired retained key became absent/local-open eligible", found, err)
	}
	n, a, err := ledger.PruneExpired(ctx)
	if err != nil || n != 4 || a != 2 {
		t.Fatal("bounded expiry retained shared debt", n, a, err)
	}
	if _, _, err = replacement.Create(ctx, ownerPool.ClusterID, makeControl(8, 8), keyFor(8)); err == nil {
		t.Fatal("expiry reset unrefilled debt")
	}
	// Maintenance-only adversarial backlog, never admission/owner authority:
	// seeded expired receipts exercise the real64-row SQL cap and ensure a
	// refused configuration change commits only restrictive prune progress.
	if _, err = lab.admin.Exec(ctx, `INSERT INTO live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,output_limit,spent,bytes_per_second,tokens_micro,refilled_at)
      SELECT $1::uuid,md5($1::uuid::text||'expired-receipt-'||g.idx)::uuid,$2,$3,$4,$5,$6,sha256(convert_to('expired-receipt-'||g.idx,'UTF8')),1,'Closed',now()-interval '3 seconds',now()-interval '1 second',now()-interval '1 second',24576,0,1,0,now()-interval '3 seconds' FROM generate_series(1,65) AS g(idx)`, root, request.Binding.ProcessEpoch, c.Fence, c.PrincipalKey[:], c.WorkloadKey[:], c.RequestDigest[:]); err != nil {
		t.Fatal("expired receipt maintenance input", err)
	}
	for _, want := range []int64{1, 0} {
		if _, _, err = replacement.Create(ctx, ownerPool.ClusterID, makeControl(8, 8), keyFor(8)); err == nil {
			t.Fatal("prune progress reset unrefilled debt")
		}
		var remaining int64
		if err = lab.admin.QueryRow(ctx, `SELECT count(*) FROM live_watch_control WHERE root_id=$1`, root).Scan(&remaining); err != nil || remaining != want {
			t.Fatal("refused Open did not commit bounded restrictive prune", remaining, want, err)
		}
	}

	t.Log("real compiled hub control facets + independently audited current owner: original receipts, exact active/closed/retired-owner viewer counts with cluster isolation, installation root uniqueness, isolated workload ceiling/release, one slot, per-watch/three-account charges, rollback, close/reopen debt, original expiry; no native/source/installed qualification")
}
