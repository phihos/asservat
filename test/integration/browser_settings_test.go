package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL transactions with distinct ingress/configuration credentials.
// Settings are synthetic protected inputs; this is not bootstrap qualification.
func browserSettingsFences(t *testing.T, ctx context.Context, admin, ingress, settingsPool *pgxpool.Pool) {
	t.Helper()
	root, epoch := "74000000-0000-4000-8000-000000000101", "74000000-0000-4000-8000-000000000102"
	projection, e := postgres.NewBrowserSettingsProjection(ctx, settingsPool, root)
	if e != nil {
		t.Fatal(e)
	}
	settings := identity.BrowserSettings{RootID: root, Epoch: epoch, Issuer: "https://id.invalid", ClientID: "console", Origin: "https://console.invalid", Revision: identity.Revision{UID: "synthetic-current-settings", Generation: 1, Digest: [32]byte{1}}, MaxLifetimeSeconds: 3600, MaxLogins: 16, MaxSessions: 16, MaxLogoutEvents: 16}
	store, e := postgres.NewBrowserSessions(ctx, ingress, settings.Binding())
	if e != nil {
		t.Fatal(e)
	}
	fresh := func(a identity.BrowserSettings) identity.BrowserSettings {
		a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
		return a
	}
	observe := func() {
		t.Helper()
		settings = fresh(settings)
		if e := projection.ObserveBrowserSettings(ctx, settings); e != nil {
			t.Fatal(e)
		}
	}
	advance := func() { settings.Revision.Generation++; settings.Revision.Digest[0]++ }
	denied := func(a identity.BrowserSettings) {
		t.Helper()
		if e := projection.ObserveBrowserSettings(ctx, fresh(a)); e == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	login := identity.BrowserLogin{ID: [32]byte{21}, Browser: [32]byte{22}, Ciphertext: []byte("synthetic-login"), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, e := admin.Exec(ctx, "INSERT INTO browser_session_root(id,epoch,enabled,max_logins,max_sessions,max_logout_events) VALUES($1,$2,true,16,16,16)", root, epoch); e != nil {
		t.Fatal(e)
	}
	if e := store.PutLogin(ctx, login); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("unqualified boolean root admitted login")
	}
	if _, e := admin.Exec(ctx, "INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)", root, epoch, login.ID[:], login.Browser[:], login.Ciphertext, login.CreatedAt, login.ExpiresAt); e != nil {
		t.Fatal(e)
	}
	observe()
	for _, binding := range []string{"issuer", "client", "origin"} {
		bad := settings.Binding()
		switch binding {
		case "issuer":
			bad.Issuer += "/wrong"
		case "client":
			bad.ClientID += "-wrong"
		case "origin":
			bad.Origin = "https://wrong.invalid"
		}
		misconfigured, e := postgres.NewBrowserSessions(ctx, ingress, bad)
		if e != nil {
			t.Fatal(e)
		}
		if e := misconfigured.PutLogin(ctx, login); !errors.Is(e, identity.ErrDenied) {
			t.Fatal("runtime binding did not match protected settings")
		}
	}
	if _, e := store.TakeLogin(ctx, login.ID, login.Browser); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("legacy challenge survived qualification")
	}

	for _, query := range []string{"SELECT ciphertext FROM browser_session LIMIT 1", "SELECT ciphertext FROM browser_login LIMIT 1", "INSERT INTO browser_session SELECT * FROM browser_session WHERE false", "UPDATE browser_session SET ciphertext='forged' WHERE false"} {
		if _, e := settingsPool.Exec(ctx, query); e == nil {
			t.Fatal("settings observer obtained credential authority")
		}
	}
	if _, e := ingress.Exec(ctx, "UPDATE browser_session_root SET fresh_until=clock_timestamp()+interval '5 seconds' WHERE id=$1", root); e == nil {
		t.Fatal("ingress renewed own settings")
	}

	r := identity.BrowserSession{ID: [32]byte{23}, Principal: identity.Principal{Issuer: settings.Issuer, ClientID: settings.ClientID, Subject: "synthetic-user", Kind: identity.Human}, ProviderSession: "synthetic-provider-session", Ciphertext: []byte("synthetic-encrypted-credentials"), CreatedAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(8 * time.Hour), RefreshAt: now.Add(time.Minute), Version: 1}
	created, e := store.CreateSession(ctx, r)
	if e != nil || !created.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("creation did not clamp to administrator maximum: %v", e)
	}
	if !created.Current(time.Now()) || created.Observation.Settings != settings.Revision || !created.Observation.ObservedAt.Equal(settings.ObservedAt) || !created.Observation.FreshUntil.Equal(settings.FreshUntil) {
		t.Fatal("creation did not preserve original configuration deadline")
	}
	csrfOnly, e := store.ReadSessionForCSRF(ctx, r.ID)
	if e != nil || !csrfOnly.Valid(time.Now()) || csrfOnly.Current(time.Now()) || csrfOnly.Observation != (identity.SessionObservation{}) {
		t.Fatal("CSRF-only lookup supplied session authority", e)
	}
	settings.MaxLifetimeSeconds = 60
	advance()
	observe()
	short, e := store.ReadSession(ctx, r.ID)
	if e != nil || !short.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("existing session not shortened: %v", e)
	}
	if !short.Current(time.Now()) || short.Observation.Settings != settings.Revision || !short.Observation.FreshUntil.Equal(settings.FreshUntil) {
		t.Fatal("current read renewed or substituted configuration observation")
	}
	settings.MaxLifetimeSeconds = 7200
	advance()
	observe()
	later, e := store.ReadSession(ctx, r.ID)
	if e != nil || !later.ExpiresAt.Equal(short.ExpiresAt) {
		t.Fatal("raising maximum extended existing session")
	}
	wrong := r
	wrong.ID = [32]byte{24}
	wrong.Principal.ClientID = "another-client"
	if _, e := store.CreateSession(ctx, wrong); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("wrong client credential accepted")
	}
	wrong.Principal = r.Principal
	wrong.Principal.Issuer = "https://another-issuer.invalid"
	if _, e := store.CreateSession(ctx, wrong); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("wrong issuer credential accepted")
	}

	bad := settings
	bad.Revision.UID = "replacement-source"
	denied(bad)
	bad = settings
	bad.Revision.Generation--
	denied(bad)
	bad = settings
	bad.Revision.Digest[1]++
	denied(bad)
	for _, binding := range []string{"issuer", "client", "origin"} {
		bad = settings
		bad.Revision.Generation++
		bad.Revision.Digest[1]++
		switch binding {
		case "issuer":
			bad.Issuer += "/new"
		case "client":
			bad.ClientID += "-new"
		case "origin":
			bad.Origin = "https://new.invalid"
		}
		denied(bad)
	}
	// A failed, older observation cannot disable a later successful read.
	if e := projection.FenceBrowserSettings(ctx, settings.ObservedAt.Add(-time.Microsecond)); e != nil {
		t.Fatal(e)
	}
	if _, e := store.ReadSession(ctx, r.ID); e != nil {
		t.Fatal("old failure fenced newer settings")
	}
	if e := projection.FenceBrowserSettings(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := store.ReadSession(ctx, r.ID); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("source failure retained identity access")
	}
	if _, e := store.ReadSessionForCSRF(ctx, r.ID); e != nil {
		t.Fatal("source failure prevented logout bootstrap")
	}
	observe()

	// Expiry after waiting for a root lock must roll back the whole operation.
	settings = fresh(settings)
	settings.FreshUntil = settings.ObservedAt.Add(150 * time.Millisecond)
	if e := projection.ObserveBrowserSettings(ctx, settings); e != nil {
		t.Fatal(e)
	}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e := tx.Exec(ctx, "SELECT id FROM browser_session_root WHERE id=$1 FOR UPDATE", root); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- store.ClaimRefresh(ctx, r.ID, 1, [32]byte{25}) }()
	time.Sleep(200 * time.Millisecond)
	if e := tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e := <-done; !errors.Is(e, identity.ErrUnavailable) {
		t.Fatalf("expired settings passed root lock: %v", e)
	}
	if _, e := store.ReadSessionForCSRF(ctx, r.ID); e != nil {
		t.Fatal("expired settings prevented CSRF-only read")
	}
	if e := store.RevokeSession(ctx, r.ID); e != nil {
		t.Fatal("expired settings prevented local logout")
	}
	event := app.LogoutEvent{Issuer: settings.Issuer, ClientID: settings.ClientID, Subject: "synthetic-user", ID: "settings-expired-logout", IssuedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if e := store.LogoutSessions(ctx, event); e != nil {
		t.Fatal("expired settings prevented signed provider logout")
	}
	observe()
	settings.Suspended = true
	advance()
	observe()
	if e := store.PutLogin(ctx, login); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("paused settings admitted login")
	}
	settings.Suspended = false
	settings.Epoch = "74000000-0000-4000-8000-000000000103"
	settings.Origin = "https://new.invalid"
	advance()
	observe()
	if e := store.PutLogin(ctx, login); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("old epoch reactivated")
	}
	bad = settings
	bad.Epoch = epoch
	bad.Revision.Generation++
	bad.Revision.Digest[1]++
	denied(bad)
	t.Log("current settings, source continuity, role separation, monotonic lifetime, outage logout, lock expiry and never-reused epochs passed")
}
