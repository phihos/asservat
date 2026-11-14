package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEnrollmentBootstrapReservationsWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run make fleet-integration or custody-integration")
	}
	var f fixture
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	u, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	config, err := pgxpool.ParseConfig("postgres://bootstrap_reserve_runtime:synthetic-bootstrap-reserve@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.TLSConfig = tlsConfig
	config.ConnConfig.Fallbacks = nil
	config.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	setup := func(active, history, clusters int) (value.BootstrapRequest, *postgres.BootstrapReservations) {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		authority := value.EnrollmentAuthority{InstallationID: uuid.NewString(), IssuerEpoch: uuid.NewString(), DeliveryProfile: "operator-channel", Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "synthetic-operator", ClientID: "console", Kind: identity.Human}, IdentityRevision: identity.Revision{UID: "id-policy", Generation: 1, Digest: [32]byte{1}}, AdministrationRevision: identity.Revision{UID: "fleet-config", Generation: 1, Digest: [32]byte{2}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), MaxActiveBootstraps: active, MaxBootstrapHistory: history, MaxClusters: clusters}
		_, err := admin.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,$3,1,$4,false,$5,$6)`, authority.InstallationID, authority.IssuerEpoch, authority.AdministrationRevision.UID, authority.AdministrationRevision.Digest[:], now, now.Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := seedSyntheticFleetObservation(ctx, admin, authority.InstallationID); err != nil {
			t.Fatal(err)
		}
		reservations, err := postgres.NewBootstrapReservations(ctx, pool, authority.InstallationID, uuid.NewString)
		if err != nil {
			t.Fatal(err)
		}
		return value.BootstrapRequest{KeyDigest: artifact.Digest{1}, DisplayName: "Synthetic production cluster", Region: "eu-test", Authority: authority}, reservations
	}
	t.Run("concurrent-same-key-and-restart-preserve-identity-expiry", func(t *testing.T) {
		request, reservations := setup(1, 1, 1)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var results []value.BootstrapIntent
		for range 8 {
			wg.Go(func() {
				r, err := reservations.ReserveBootstrap(ctx, request)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			})
		}
		wg.Wait()
		if len(results) != 8 {
			t.Fatal("duplicate reservation failed")
		}
		for _, r := range results {
			if r.Slot.ID != results[0].Slot.ID || r.Slot.Binding != results[0].Slot.Binding || !r.Slot.NotAfter.Equal(results[0].Slot.NotAfter) || r.Credential != nil || r.Issued {
				t.Fatal("reservation replay changed effect identity")
			}
		}
		restarted, err := postgres.NewBootstrapReservations(ctx, pool, request.Authority.InstallationID, uuid.NewString)
		if err != nil {
			t.Fatal(err)
		}
		again, err := restarted.ReserveBootstrap(ctx, request)
		if err != nil || again.Slot.ID != results[0].Slot.ID || !again.Slot.NotBefore.Equal(results[0].Slot.NotBefore) {
			t.Fatal("restart renewed reservation", err)
		}
		changed := request
		changed.DisplayName = "another cluster"
		if _, err = restarted.ReserveBootstrap(ctx, changed); !errors.Is(err, value.ErrConflict) {
			t.Fatal("same key changed request", err)
		}
		var n int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM fleet_bootstrap WHERE installation_id=$1", request.Authority.InstallationID).Scan(&n); err != nil || n != 0 {
			t.Fatal("reservation minted usable token", n, err)
		}
	})
	for _, limit := range []string{"active", "cluster"} {
		t.Run("last-"+limit+"-slot", func(t *testing.T) {
			active, clusters := 1, 16
			if limit == "cluster" {
				active, clusters = 16, 1
			}
			request, reservations := setup(active, 16, clusters)
			var wg sync.WaitGroup
			var allowed, denied atomic.Int64
			for i := range 8 {
				r := request
				r.KeyDigest[0] = byte(i + 1)
				wg.Go(func() {
					_, err := reservations.ReserveBootstrap(ctx, r)
					if err == nil {
						allowed.Add(1)
					} else if errors.Is(err, value.ErrCapacity) {
						denied.Add(1)
					} else {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			if allowed.Load() != 1 || denied.Load() != 7 {
				t.Fatal("quota race", allowed.Load(), denied.Load())
			}
		})
	}
	t.Run("expired-history-still-counts", func(t *testing.T) {
		request, reservations := setup(1, 1, 16)
		a := request.Authority
		actor, _ := json.Marshal(a.Actor)
		_, err := admin.Exec(ctx, `INSERT INTO fleet_bootstrap_intent(installation_id,id,actor_digest,key_digest,request_digest,actor_json,identity_uid,identity_generation,identity_digest,trust_uid,trust_generation,trust_digest,cluster_id,peer_id,issuer_epoch,delivery_profile,display_name,region,not_before,not_after) VALUES($1,$2,$3,$3,$3,$4,'history-identity',1,$3,'history-trust',1,$3,$5,$6,$7,'operator-channel','retained history','eu-test',statement_timestamp()-interval '6 minutes',statement_timestamp()-interval '1 minute')`, a.InstallationID, uuid.NewString(), a.IdentityRevision.Digest[:], actor, uuid.NewString(), uuid.NewString(), a.IssuerEpoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = reservations.ReserveBootstrap(ctx, request); !errors.Is(err, value.ErrCapacity) {
			t.Fatal("retained history bypassed", err)
		}
	})
	for _, mode := range []string{"active", "history", "cluster"} {
		t.Run("preexisting-bootstrap-"+mode+"-counts", func(t *testing.T) {
			active, history, clusters := 8, 16, 16
			switch mode {
			case "active":
				active = 1
			case "history":
				active, history = 1, 1
			case "cluster":
				clusters = 1
			}
			request, reservations := setup(active, history, clusters)
			a := request.Authority
			before, after := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
			if mode == "history" {
				before, after = before.Add(-2*time.Minute), after.Add(-2*time.Minute)
			}
			_, err := admin.Exec(ctx, `INSERT INTO fleet_bootstrap(installation_id,id,cluster_id,peer_id,issuer_epoch,secret_sha256,not_before,not_after,issue_authority_digest,issue_audit_id,issue_audit_key,issue_audit_version,issue_audit_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$6,$9,'synthetic-preexisting','v1',$6)`, a.InstallationID, uuid.NewString(), uuid.NewString(), uuid.NewString(), a.IssuerEpoch, a.IdentityRevision.Digest[:], before, after, uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reservations.ReserveBootstrap(ctx, request); !errors.Is(err, value.ErrCapacity) {
				t.Fatal("preexisting bootstrap bypassed quota", mode, err)
			}
		})
	}
	t.Run("registered-cluster-still-counts", func(t *testing.T) {
		request, reservations := setup(16, 16, 1)
		a := request.Authority
		_, err := admin.Exec(ctx, `INSERT INTO fleet_peer(installation_id,peer_id,cluster_id,issuer_epoch,role,revision,not_after) VALUES($1,$2,$3,$4,'connector',1,clock_timestamp()-interval '1 minute')`, a.InstallationID, uuid.NewString(), uuid.NewString(), a.IssuerEpoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = reservations.ReserveBootstrap(ctx, request); !errors.Is(err, value.ErrCapacity) {
			t.Fatal("retained cluster silently refunded", err)
		}
	})
	for _, mode := range []string{"suspended", "recovery", "epoch", "revision", "expired-lock"} {
		t.Run(mode, func(t *testing.T) {
			request, reservations := setup(8, 16, 16)
			a := request.Authority
			sql := ""
			switch mode {
			case "suspended":
				sql = "UPDATE fleet_trust SET suspended=true WHERE installation_id=$1"
			case "recovery":
				sql = "UPDATE fleet_trust SET suspended=true WHERE installation_id=$1"
			case "epoch":
				sql = "UPDATE fleet_trust SET issuer_epoch=gen_random_uuid() WHERE installation_id=$1"
			case "revision":
				sql = "UPDATE fleet_trust SET source_generation=source_generation+1 WHERE installation_id=$1"
			}
			if sql != "" {
				if _, err := admin.Exec(ctx, sql, a.InstallationID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "expired-lock" {
				request.Authority.ValidUntil = time.Now().Add(200 * time.Millisecond)
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", a.InstallationID); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := reservations.ReserveBootstrap(ctx, request); done <- err }()
				time.Sleep(300 * time.Millisecond)
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err == nil {
					t.Fatal("expired blocked operator accepted")
				}
				return
			}
			if _, err := reservations.ReserveBootstrap(ctx, request); err == nil {
				t.Fatal("unsafe trust reserved credentials", mode)
			}
		})
	}
	// mode=combined: the installation's own connector peer gets a slot for
	// its fixed generated IDs, a live slot resumes or stays pending, a slot
	// that expired without activation (unclaimed, or claimed by a failed
	// enrollment) is replaced and an activated enrollment ends issuance.
	t.Run("local-fixed-binding", func(t *testing.T) {
		request, _ := setup(1, 16, 1)
		a := request.Authority
		cluster, peer := uuid.NewString(), uuid.NewString()
		local, err := postgres.NewLocalBootstrapReservations(ctx, pool, a.InstallationID, cluster, peer, uuid.NewString)
		if err != nil {
			t.Fatal(err)
		}
		first, err := local.ReserveBootstrap(ctx, request)
		if err != nil || first.Slot.Binding.ClusterID != cluster || first.Slot.Binding.PeerID != peer {
			t.Fatal("local slot not bound to the fixed IDs", err)
		}
		again, err := local.ReserveBootstrap(ctx, request)
		if err != nil || again.Slot.ID != first.Slot.ID {
			t.Fatal("live local slot not resumed", err)
		}
		other := request
		other.KeyDigest[0] = 9
		if _, err = local.ReserveBootstrap(ctx, other); !errors.Is(err, value.ErrPending) {
			t.Fatal("second live local slot", err)
		}
		// Expire the installation's slots (fixture-only trigger bypass).
		expire := func() {
			t.Helper()
			if _, err := admin.Exec(ctx, `ALTER TABLE fleet_bootstrap_intent DISABLE TRIGGER bootstrap_intent_guard; ALTER TABLE fleet_bootstrap DISABLE TRIGGER bootstrap_claim_guard; UPDATE fleet_bootstrap_intent SET not_before=not_before-interval '6 minutes',not_after=not_after-interval '6 minutes' WHERE installation_id='`+a.InstallationID+`'; UPDATE fleet_bootstrap SET claimed_at=claimed_at-interval '6 minutes',not_before=not_before-interval '6 minutes',not_after=not_after-interval '6 minutes' WHERE installation_id='`+a.InstallationID+`'; ALTER TABLE fleet_bootstrap ENABLE TRIGGER bootstrap_claim_guard; ALTER TABLE fleet_bootstrap_intent ENABLE TRIGGER bootstrap_intent_guard`); err != nil {
				t.Fatal(err)
			}
		}
		expire()
		replaced, err := local.ReserveBootstrap(ctx, other)
		if err != nil || replaced.Slot.ID == first.Slot.ID || replaced.Slot.Binding != first.Slot.Binding {
			t.Fatal("expired unclaimed local slot not replaced for the same peer", err)
		}
		claim := func(slot string, k byte) {
			t.Helper()
			if _, err := admin.Exec(ctx, `INSERT INTO fleet_bootstrap(installation_id,id,cluster_id,peer_id,issuer_epoch,secret_sha256,not_before,not_after,issue_authority_digest,issue_audit_id,issue_audit_key,issue_audit_version,issue_audit_sha256) SELECT installation_id,id,cluster_id,peer_id,issuer_epoch,$2,not_before,not_after,$2,id,'synthetic-local','v1',$2 FROM fleet_bootstrap_intent WHERE installation_id=$1 AND id=$3`, a.InstallationID, bytes.Repeat([]byte{k}, 32), slot); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, `UPDATE fleet_bootstrap SET claimed_at=clock_timestamp(),public_key_sha256=$3 WHERE installation_id=$1 AND id=$2`, a.InstallationID, slot, bytes.Repeat([]byte{k}, 32)); err != nil {
				t.Fatal(err)
			}
		}
		// A live claimed slot is an enrollment in progress: no second slot.
		claim(replaced.Slot.ID, 3)
		third := request
		third.KeyDigest[0] = 7
		if _, err = local.ReserveBootstrap(ctx, third); !errors.Is(err, value.ErrPending) {
			t.Fatal("live claimed local slot replaced", err)
		}
		// Claimed but never activated before expiry: it can no longer
		// enroll, so a new slot replaces it.
		expire()
		reissued, err := local.ReserveBootstrap(ctx, third)
		if err != nil || reissued.Slot.ID == replaced.Slot.ID || reissued.Slot.Binding != first.Slot.Binding {
			t.Fatal("failed claimed local slot not re-issued", err)
		}
		// An activated enrollment of the peer ends local issuance, also after
		// its slot expired (fixture-only activation row without its chain).
		claim(reissued.Slot.ID, 4)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO cluster_bootstrap_activation(installation_id,bootstrap_id,root_id,peer_id,cluster_id,issuer_epoch,lineage_id,claim_audit_digest,public_key,key_digest,source_uid,source_generation,protection_digest,validity_seconds,rotation_seconds,reserved_at,audit_acknowledged_at,audit_object_key,audit_object_version,audit_object_etag,audit_object_bytes,audit_object_sha256,activated_at)
			SELECT installation_id,id,gen_random_uuid(),peer_id,cluster_id,issuer_epoch,gen_random_uuid(),$3,$3,$3,gen_random_uuid(),1,$3,3600,60,clock_timestamp(),clock_timestamp(),'synthetic','v1','etag',1,$3,clock_timestamp() FROM fleet_bootstrap WHERE installation_id=$1 AND id=$2`, a.InstallationID, reissued.Slot.ID, bytes.Repeat([]byte{4}, 32)); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		expire()
		if _, err = local.ReserveBootstrap(ctx, request); !errors.Is(err, value.ErrLocalBootstrapConsumed) {
			t.Fatal("activated local enrollment replaced", err)
		}
	})
	t.Run("role-and-immutable-record", func(t *testing.T) {
		request, reservations := setup(8, 16, 16)
		if _, err := reservations.ReserveBootstrap(ctx, request); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"UPDATE fleet_bootstrap_intent SET not_after=not_after+interval '1 minute' WHERE installation_id=$1", "DELETE FROM fleet_bootstrap_intent WHERE installation_id=$1", "UPDATE fleet_peer SET enabled=true WHERE installation_id=$1", "UPDATE fleet_trust SET suspended=false WHERE installation_id=$1", "UPDATE fleet_bootstrap SET revoked=false WHERE installation_id=$1"} {
			if _, err := pool.Exec(ctx, sql, request.Authority.InstallationID); err == nil {
				t.Fatal("reservation role widened authority")
			}
		}
		if _, err := admin.Exec(ctx, "UPDATE fleet_bootstrap_intent SET display_name='replacement' WHERE installation_id=$1", request.Authority.InstallationID); err == nil {
			t.Fatal("immutable original changed")
		}
	})
}
