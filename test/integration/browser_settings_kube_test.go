package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func testBrowserSettingsSource(t *testing.T, ctx context.Context, c *rest.Config, cluster string, control cfg.NamespaceRef, readerToken, dsn string) {
	t.Helper()
	admin, e := kubernetes.NewForConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../examples/browser-settings.json")
	if e != nil {
		t.Fatal(e)
	}
	var wire contracts.BrowserSettings
	if e = json.Unmarshal(data, &wire); e != nil {
		t.Fatal(e)
	}
	object, e := admin.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "browser-settings"}, Data: map[string]string{"browser.json": string(data)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: c.Host, BearerToken: readerToken, TLSClientConfig: rest.TLSClientConfig{CAData: c.CAData, CAFile: c.CAFile, ServerName: c.ServerName}}
	client, e := kube.NewPermissionClient(limited, cluster, control, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := kube.NewBrowserSettingsClient(client, object.Name, string(object.UID), wire.RootID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := reader.BrowserSettings(ctx); e == nil {
		t.Fatal("browser settings read without explicit named RBAC")
	}
	_, e = admin.RbacV1().Roles(control.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "browser-settings-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().RoleBindings(control.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "browser-settings-reader"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "permission-reader", Namespace: control.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "browser-settings-reader"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	first, e := reader.BrowserSettings(ctx)
	if e != nil || first.Suspended || first.Revision.UID != string(object.UID) {
		t.Fatalf("settings read failed: %v", e)
	}
	limitedAPI, e := kubernetes.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := limitedAPI.CoreV1().ConfigMaps(control.Name).Patch(ctx, object.Name, types.MergePatchType, []byte(`{"data":{"browser.json":"forged"}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reader can change browser settings")
	}
	if e := limitedAPI.CoreV1().ConfigMaps(control.Name).Delete(ctx, object.Name, meta.DeleteOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("reader can replace browser settings")
	}

	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	poolFor := func(user, password string) *pgxpool.Pool {
		t.Helper()
		pc, e := pgxpool.ParseConfig("postgres://" + user + ":" + password + "@" + address + "/custody_test?sslmode=disable")
		if e != nil {
			t.Fatal(e)
		}
		pc.ConnConfig.TLSConfig = tlsConfig
		pc.ConnConfig.Fallbacks = nil
		pc.MaxConns = 2
		pool, e := pgxpool.NewWithConfig(ctx, pc)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	projection, e := postgres.NewBrowserSettingsProjection(ctx, poolFor("browser_settings_runtime", "synthetic-browser-settings"), wire.RootID)
	if e != nil {
		t.Fatal(e)
	}
	store, e := postgres.NewBrowserSessions(ctx, poolFor("browser_runtime", "synthetic-browser"), first.Binding())
	if e != nil {
		t.Fatal(e)
	}
	observer := app.BrowserSettingsObserver{Source: reader, Projection: projection, Now: time.Now}
	if e := observer.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	login := identity.BrowserLogin{ID: [32]byte{81}, Browser: [32]byte{82}, Ciphertext: []byte("synthetic-encrypted-login"), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if e := store.PutLogin(ctx, login); e != nil {
		t.Fatal(e)
	}
	wire.Revision++
	wire.Suspended = true
	data, e = json.Marshal(wire)
	if e != nil {
		t.Fatal(e)
	}
	object.Data["browser.json"] = string(data)
	object, e = admin.CoreV1().ConfigMaps(control.Name).Update(ctx, object, meta.UpdateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if e := observer.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := store.TakeLogin(ctx, login.ID, login.Browser); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("Kubernetes suspension did not stop callback")
	}
	wire.Revision++
	wire.Suspended = false
	data, e = json.Marshal(wire)
	if e != nil {
		t.Fatal(e)
	}
	object.Data["browser.json"] = string(data)
	object, e = admin.CoreV1().ConfigMaps(control.Name).Update(ctx, object, meta.UpdateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if e := observer.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := store.TakeLogin(ctx, login.ID, login.Browser); e != nil {
		t.Fatal(e)
	}
	if e := admin.CoreV1().ConfigMaps(control.Name).Delete(ctx, object.Name, meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	object.ResourceVersion = ""
	object.UID = ""
	if _, e := admin.CoreV1().ConfigMaps(control.Name).Create(ctx, object, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if e := observer.Reconcile(ctx); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("same-name replacement accepted")
	}
	if e := store.PutLogin(ctx, login); !errors.Is(e, identity.ErrUnavailable) {
		t.Fatal("source replacement did not fence SQL")
	}
	t.Log("real named Kubernetes RBAC, current settings to SQL, suspension and source replacement fencing passed")
}
