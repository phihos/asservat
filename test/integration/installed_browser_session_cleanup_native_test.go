package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Only fixture-owned opaque rows are seeded/read. They are not usable provider
// credentials, and no session authority comes from this administrative setup.
type installedBrowserCleanupRows struct {
	login                       [2]identity.BrowserLogin
	session                     [2]identity.BrowserSession
	logoutID                    [2][32]byte
	logoutIssued, logoutExpires [2]time.Time
}

func newInstalledBrowserCleanupRows(cfg contracts.BrowserSettings, n time.Time, nonce string) installedBrowserCleanupRows {
	n = n.UTC().Truncate(time.Microsecond)
	var p installedBrowserCleanupRows
	for i := range 2 {
		id := func(kind string) [32]byte { return sha256.Sum256([]byte(nonce + fmt.Sprint(i) + kind)) }
		p.login[i] = identity.BrowserLogin{ID: id("login"), Browser: id("browser"), Ciphertext: []byte("synthetic-opaque-login"), CreatedAt: n, ExpiresAt: n.Add(4 * time.Minute)}
		p.session[i] = identity.BrowserSession{ID: id("session"), Principal: identity.Principal{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Subject: "synthetic-cleanup-" + nonce, Kind: identity.Human}, ProviderSession: "synthetic-provider-" + nonce, Ciphertext: []byte("synthetic-opaque-session"), CreatedAt: n, AuthenticatedAt: n, ExpiresAt: n.Add(3 * time.Minute), RefreshAt: n.Add(time.Minute), Version: 1}
		p.logoutID[i], p.logoutIssued[i], p.logoutExpires[i] = id("logout"), n, n.Add(25*time.Hour)
	}
	p.login[0].CreatedAt, p.login[0].ExpiresAt = n.Add(-2*time.Minute), n.Add(-time.Minute)
	p.session[0].CreatedAt, p.session[0].AuthenticatedAt, p.session[0].ExpiresAt, p.session[0].RefreshAt = n.Add(-2*time.Hour), n.Add(-2*time.Hour), n.Add(-time.Hour), n.Add(-90*time.Minute)
	p.logoutIssued[0], p.logoutExpires[0] = n.Add(-2*time.Hour), n.Add(-time.Hour)
	return p
}

type installedBrowserCleanupRoot struct {
	ID, Epoch, Issuer, Client, Origin, SourceUID   string
	Enabled                                        bool
	MaxLogins, MaxSessions, MaxLogout, MaxLifetime int
	Generation                                     int64
	Digest                                         [32]byte
}
type browserCleanupRowReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readInstalledBrowserCleanupRoot(ctx context.Context, db browserCleanupRowReader, id string) (installedBrowserCleanupRoot, time.Time, time.Time, error) {
	var s installedBrowserCleanupRoot
	var digest []byte
	var observed, fresh time.Time
	err := db.QueryRow(ctx, `SELECT id::text,epoch::text,issuer,client_id,origin,enabled,max_logins,max_sessions,max_logout_events,max_lifetime_seconds,source_uid,source_generation,source_digest,observed_at,fresh_until FROM browser_session_root WHERE id=$1`, id).Scan(&s.ID, &s.Epoch, &s.Issuer, &s.Client, &s.Origin, &s.Enabled, &s.MaxLogins, &s.MaxSessions, &s.MaxLogout, &s.MaxLifetime, &s.SourceUID, &s.Generation, &digest, &observed, &fresh)
	if err == nil && len(digest) != 32 {
		err = fmt.Errorf("invalid root digest length")
	}
	copy(s.Digest[:], digest)
	return s, observed, fresh, err
}
func (p installedBrowserCleanupRows) state(ctx context.Context, db browserCleanupRowReader, root string) ([3]int, []byte, error) {
	var counts [3]int
	var live []byte
	err := db.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM browser_login WHERE root_id=$1 AND id=$2),
 (SELECT count(*) FROM browser_session WHERE root_id=$1 AND id=$3),
 (SELECT count(*) FROM browser_logout WHERE root_id=$1 AND id=$4),
 jsonb_build_object('login',(SELECT to_jsonb(l) FROM browser_login l WHERE root_id=$1 AND id=$5),
 'session',(SELECT to_jsonb(s) FROM browser_session s WHERE root_id=$1 AND id=$6),
 'receipt',(SELECT to_jsonb(l) FROM browser_logout l WHERE root_id=$1 AND id=$7))`, root, p.login[0].ID[:], p.session[0].ID[:], p.logoutID[0][:], p.login[1].ID[:], p.session[1].ID[:], p.logoutID[1][:]).Scan(&counts[0], &counts[1], &counts[2], &live)
	return counts, live, err
}

// Run only after the browser focus's foreground clients have joined. HTTP
// login/session creation can prune too, so overlapping them would not prove
// that the actual installed worker called housekeeping.
func qualifyInstalledBrowserSessionCleanup(t *testing.T, parent context.Context, admin *pgxpool.Pool, api kubernetes.Interface, namespace, installation string, diagnose func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 75*time.Second)
	defer cancel()
	var pending pgx.Tx
	fail := func(stage string) {
		t.Helper()
		if pending != nil {
			rollback, stop := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
			_ = pending.Rollback(rollback)
			stop()
			pending = nil
		}
		t.Log("installed browser-session cleanup refused at " + stage)
		diagnose()
		t.Fatal("installed browser-session cleanup: " + stage)
	}
	cfgMap, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, contracts.OwnerBrowserSettingsName(installation), meta.GetOptions{})
	if err != nil {
		fail("settings-source")
		return
	}
	var cfg contracts.BrowserSettings
	if json.Unmarshal([]byte(cfgMap.Data["browser.json"]), &cfg) != nil || cfg.SchemaVersion != "browser-settings/v1" || cfg.Suspended || cfg.MaxLifetimeSeconds < 180 {
		fail("settings-shape")
		return
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		fail("seed-begin")
		return
	}
	pending = tx
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT id FROM browser_session_root WHERE id=$1 FOR UPDATE", cfg.RootID); err != nil {
		fail("seed-lock")
		return
	}
	original, observed, fresh, err := readInstalledBrowserCleanupRoot(ctx, tx, cfg.RootID)
	if err != nil || original.Epoch != cfg.SessionEpoch || original.Issuer != cfg.Issuer || original.Client != cfg.ClientID || original.Origin != cfg.Origin || !original.Enabled || original.SourceUID != string(cfgMap.UID) || original.Generation != cfg.Revision || original.MaxLogins != cfg.MaxLogins || original.MaxSessions != cfg.MaxSessions || original.MaxLogout != cfg.MaxLogoutEvents || original.MaxLifetime != cfg.MaxLifetimeSeconds || !time.Now().Before(fresh) {
		fail("installed-root-binding")
		return
	}
	var slots [3]int
	if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM browser_login WHERE root_id=$1),(SELECT count(*) FROM browser_session WHERE root_id=$1),(SELECT count(*) FROM browser_logout WHERE root_id=$1)`, cfg.RootID).Scan(&slots[0], &slots[1], &slots[2]); err != nil || slots[0]+2 > cfg.MaxLogins || slots[1]+2 > cfg.MaxSessions || slots[2]+2 > cfg.MaxLogoutEvents {
		fail("original-ceilings")
		return
	}
	var n time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&n); err != nil {
		fail("seed-clock")
		return
	}
	p := newInstalledBrowserCleanupRows(cfg, n, custodyID())
	for i := range 2 {
		l, s := p.login[i], p.session[i]
		if _, err = tx.Exec(ctx, `INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, cfg.RootID, cfg.SessionEpoch, l.ID[:], l.Browser[:], l.Ciphertext, l.CreatedAt, l.ExpiresAt); err != nil {
			fail("seed-login")
			return
		}
		if _, err = tx.Exec(ctx, `INSERT INTO browser_session(root_id,epoch,id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,refresh_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, cfg.RootID, cfg.SessionEpoch, s.ID[:], s.Principal.Issuer, s.Principal.ClientID, s.Principal.Subject, s.ProviderSession, s.Ciphertext, s.CreatedAt, s.AuthenticatedAt, s.ExpiresAt, s.RefreshAt, s.Version); err != nil {
			fail("seed-session")
			return
		}
		if _, err = tx.Exec(ctx, `INSERT INTO browser_logout(root_id,epoch,id,issuer,client_id,subject,provider_session,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,'',$7,$8)`, cfg.RootID, cfg.SessionEpoch, p.logoutID[i][:], cfg.Issuer, cfg.ClientID, s.Principal.Subject, p.logoutIssued[i], p.logoutExpires[i]); err != nil {
			fail("seed-receipt")
			return
		}
	}
	counts, live, err := p.state(ctx, tx, cfg.RootID)
	if err != nil || counts != ([3]int{1, 1, 1}) {
		fail("seed-readback")
		return
	}
	if err = tx.Commit(ctx); err != nil {
		fail("seed-commit")
		return
	}
	pending = nil
	// Never touch product sessions. Exact synthetic-ID cleanup runs only after
	// observation finishes; it cannot supply a successful expiry observation.
	defer func() {
		end, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
		defer cancel()
		for _, q := range []struct {
			table string
			ids   [][]byte
		}{{"browser_login", [][]byte{p.login[0].ID[:], p.login[1].ID[:]}}, {"browser_session", [][]byte{p.session[0].ID[:], p.session[1].ID[:]}}, {"browser_logout", [][]byte{p.logoutID[0][:], p.logoutID[1][:]}}} {
			if _, err := admin.Exec(end, "DELETE FROM "+q.table+" WHERE root_id=$1 AND id=ANY($2::bytea[])", cfg.RootID, q.ids); err != nil {
				t.Error("synthetic cleanup rows not retired")
			}
		}
	}()
	started := time.Now()
	polls := 0
	for ctx.Err() == nil {
		polls++
		current, nextObserved, nextFresh, e := readInstalledBrowserCleanupRoot(ctx, admin, cfg.RootID)
		if e != nil {
			if ctx.Err() != nil {
				fail("expiry-observation-timeout")
			} else {
				fail("root-read")
			}
			return
		}
		if current != original || nextObserved.Before(observed) || !nextFresh.After(nextObserved) || nextFresh.Sub(nextObserved) > 5*time.Second {
			fail("root-changed")
			return
		}
		remaining, currentLive, e := p.state(ctx, admin, cfg.RootID)
		if e != nil {
			if ctx.Err() != nil {
				fail("expiry-observation-timeout")
			} else {
				fail("live-state-read")
			}
			return
		}
		if !bytes.Equal(live, currentLive) {
			fail("live-state-changed")
			return
		}
		if remaining == ([3]int{}) {
			t.Logf("installed browser-session cleanup: actual worker removed 3 expired rows; 3 live controls/root binding unchanged; claim fields NULL unchanged; observed_after=%s readonly_polls=%d", time.Since(started), polls)
			return
		}
		if installedJourneyPause(ctx, 2*time.Second) != nil {
			break
		}
	}
	fail("expiry-observation-timeout")
}
