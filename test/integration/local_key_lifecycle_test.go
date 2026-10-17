package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	authentication "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type shortKeySource struct{ app.KeyMaterialReader }

func (s shortKeySource) ReadKeyMaterial(ctx context.Context) (app.KeyMaterial, error) {
	m, e := s.KeyMaterialReader.ReadKeyMaterial(ctx)
	m.Configuration.FreshUntil = m.Configuration.ObservedAt.Add(400 * time.Millisecond)
	return m, e
}

func TestLocalKeyLifecycleWithRealKubernetesSQL(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration for owned Kubernetes/PostgreSQL fixtures")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var f fixture
	if json.Unmarshal(raw, &f) != nil || f.Postgres == "" || len(f.Clusters) == 0 {
		t.Fatal("missing lifecycle fixtures")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	admin, e := kubernetes.NewForConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	ns, e := admin.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "local-key-lifecycle", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	scope := value.KeyScope{InstallationID: custodyID(), Purpose: "artifact", KeyID: "fixture"}
	cluster := custodyID()
	epoch := "00000000-0000-4000-8000-000000000093"
	sqlAdmin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(sqlAdmin.Close)
	_, e = sqlAdmin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-local-keys',1,$3,false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')", scope.InstallationID, epoch, bytes.Repeat([]byte{97}, 32))
	if e != nil {
		t.Fatal(e)
	}
	if _, err := seedSyntheticFleetObservation(ctx, sqlAdmin, scope.InstallationID); err != nil {
		t.Fatal(err)
	}
	u, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	pc, e := pgxpool.ParseConfig("postgres://local_keys_runtime:synthetic-local-keys@" + address + "/custody_test?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 4
	pool, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	materials := [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)}
	for _, m := range materials {
		if _, e = rand.Read(m); e != nil {
			t.Fatal(e)
		}
		defer clear(m)
	}
	secret := func(name string, purpose string, active int, versions []int, material [][]byte) *core.Secret {
		t.Helper()
		keys := []any{}
		for i, v := range versions {
			keys = append(keys, map[string]any{"version": v, "material": material[i]})
		}
		payload, e := json.Marshal(map[string]any{"format": "asservat-local-keys/v1", "installationID": scope.InstallationID, "purpose": purpose, "keyID": scope.KeyID, "activeVersion": active, "keys": keys})
		if e != nil {
			t.Fatal(e)
		}
		defer clear(payload)
		immutable := true
		s, e := admin.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeOpaque, Immutable: &immutable, Data: map[string][]byte{"keys.json": payload}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	firstSecret := secret("roots-v1", "artifact", 1, []int{1}, materials[:1])
	ref := func(s *core.Secret) contracts.LocalKeySecretReference {
		sum := sha256.Sum256(s.Data["keys.json"])
		return contracts.LocalKeySecretReference{Name: s.Name, UID: string(s.UID), SHA256: hex.EncodeToString(sum[:])}
	}
	wire := contracts.LocalKeyConfiguration{Format: "asservat-local-key-configuration/v1", InstallationID: scope.InstallationID, Purpose: scope.Purpose, KeyID: scope.KeyID, RecoveryEpoch: epoch, Revision: 1, Secret: ref(firstSecret)}
	document, _ := json.Marshal(wire)
	object, e := admin.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "artifact-key"}, Data: map[string]string{"keys.json": string(document)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	apply := func(w contracts.LocalKeyConfiguration) {
		t.Helper()
		b, e := json.Marshal(w)
		if e != nil {
			t.Fatal(e)
		}
		object.Data["keys.json"] = string(b)
		object, e = admin.CoreV1().ConfigMaps(ns.Name).Update(ctx, object, meta.UpdateOptions{})
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e = admin.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "key-service"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	token, e := admin.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, "key-service", &authentication.TokenRequest{Spec: authentication.TokenRequestSpec{}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	limited := &rest.Config{Host: c.Host, BearerToken: token.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: c.CAData, CAFile: c.CAFile}}
	client, e := kube.NewPermissionClient(limited, cluster, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	source, e := kube.NewLocalKeySource(client, object.Name, string(object.UID), scope)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = source.ReadKeyMaterial(ctx); e == nil {
		t.Fatal("key material read without RBAC")
	}
	_, e = admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "local-key-namespace-reader"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	subject := []rbac.Subject{{Kind: "ServiceAccount", Name: "key-service", Namespace: ns.Name}}
	_, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "local-key-namespace-reader"}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "local-key-namespace-reader"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	names := []string{"roots-v1", "roots-v2", "changed", "removed", "rolled-active", "reused-audit"}
	_, e = admin.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "keys"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name, "audit-key"}, Verbs: []string{"get"}}, {APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: names, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = admin.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "keys"}, Subjects: subject, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "keys"}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	restricted, e := kubernetes.NewForConfig(limited)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restricted.CoreV1().Secrets(ns.Name).List(ctx, meta.ListOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("service can enumerate Secrets")
	}
	if _, e = restricted.CoreV1().Secrets(ns.Name).Patch(ctx, firstSecret.Name, types.MergePatchType, []byte(`{"data":{}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("service can mutate key Secret")
	}
	if _, e = restricted.CoreV1().ConfigMaps(ns.Name).Patch(ctx, object.Name, types.MergePatchType, []byte(`{"data":{}}`), meta.PatchOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("service can select own configuration")
	}
	ledger, e := postgres.NewLocalKeyConfigurations(ctx, pool, scope, cluster, string(ns.UID), string(object.UID))
	if e != nil {
		t.Fatal(e)
	}
	load := func() (*kms.ProtectedLocalOperations, error) {
		return kms.LoadProtectedLocalOperations(ctx, scope, source, ledger, time.Now)
	}
	first, e := load()
	if e != nil {
		t.Fatal("load pinned protected key", e)
	}
	tls1 := newKeyTLSFor(t, scope.InstallationID, "artifact", nil, first, nil)
	writer1, e := kms.NewRemoteSealer(tls1.server.URL, scope, keyAuthority, tls1.clients["collector"])
	if e != nil {
		t.Fatal(e)
	}
	binding, plain := []byte("synthetic exact artifact binding"), []byte("synthetic keyset")
	sealed, e := writer1.Seal(ctx, plain, binding)
	if e != nil {
		t.Fatal("protected wrap", e)
	}
	secondSecret := secret("roots-v2", "artifact", 2, []int{1, 2}, materials[:2])
	wire.Revision = 2
	wire.Secret = ref(secondSecret)
	apply(wire)
	second, e := load()
	if e != nil {
		t.Fatal("additive rotation", e)
	}
	if _, e = writer1.Seal(ctx, plain, binding); e == nil {
		t.Fatal("old process used replaced configuration")
	}
	tls2 := newKeyTLSFor(t, scope.InstallationID, "artifact", nil, second, nil)
	writer2, e := kms.NewRemoteSealer(tls2.server.URL, scope, keyAuthority, tls2.clients["collector"])
	if e != nil {
		t.Fatal(e)
	}
	reader2, e := kms.NewRemoteOpener(tls2.server.URL, scope, keyAuthority, tls2.clients["acquisition"])
	if e != nil {
		t.Fatal(e)
	}
	defer reader2.Close()
	got, e := reader2.Open(ctx, sealed, binding)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("rotation lost retained key", e)
	}
	clear(got)
	fresh, e := writer2.Seal(ctx, plain, binding)
	if e != nil || !strings.HasSuffix(fresh.Reference, "/2") {
		t.Fatal("new wrap did not use active v2", e)
	}
	old := wire
	old.Revision = 1
	old.Secret = ref(firstSecret)
	apply(old)
	if _, e = load(); e == nil {
		t.Fatal("restarted service accepted rollback")
	}
	if _, e = writer1.Seal(ctx, plain, binding); e == nil {
		t.Fatal("old process resumed after rollback")
	}
	apply(wire)
	wire.Revision = 3
	wire.Suspended = true
	apply(wire)
	if _, e = load(); e == nil {
		t.Fatal("suspended configuration loaded")
	}
	if _, e = reader2.Open(ctx, sealed, binding); e == nil {
		t.Fatal("suspension retained access")
	}
	old = wire
	old.Revision = 2
	old.Suspended = false
	apply(old)
	if _, e = load(); e == nil {
		t.Fatal("suspension forgotten after restart")
	}
	wire.Revision = 4
	wire.Suspended = false
	apply(wire)
	current, e := load()
	if e != nil {
		t.Fatal("explicit resume", e)
	}
	for _, tc := range []struct {
		name     string
		active   int
		versions []int
		material [][]byte
	}{
		{"changed", 2, []int{1, 2}, [][]byte{materials[2], materials[1]}},
		{"removed", 2, []int{2}, [][]byte{materials[1]}},
		{"rolled-active", 1, []int{1, 2}, materials[:2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := wire
			candidate.Revision = 5
			candidate.Secret = ref(secret(tc.name, "artifact", tc.active, tc.versions, tc.material))
			apply(candidate)
			if _, e = load(); e == nil {
				t.Fatal("unsafe key transition accepted")
			}
			apply(wire)
		})
	}
	t.Run("cross-purpose-material-reuse", func(t *testing.T) {
		a := wire
		a.Purpose = "audit"
		a.Revision = 1
		a.Secret = ref(secret("reused-audit", "audit", 1, []int{1}, materials[:1]))
		b, _ := json.Marshal(a)
		cm, e := admin.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "audit-key"}, Data: map[string]string{"keys.json": string(b)}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		scope2 := scope
		scope2.Purpose = "audit"
		source2, e := kube.NewLocalKeySource(client, cm.Name, string(cm.UID), scope2)
		if e != nil {
			t.Fatal(e)
		}
		ledger2, e := postgres.NewLocalKeyConfigurations(ctx, pool, scope2, cluster, string(ns.UID), string(cm.UID))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = kms.LoadProtectedLocalOperations(ctx, scope2, source2, ledger2, time.Now); e == nil {
			t.Fatal("same material used for two purposes")
		}
	})
	t.Run("expiry-during-sql-lock", func(t *testing.T) {
		tx, e := sqlAdmin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "SELECT 1 FROM local_key_configuration WHERE installation_id=$1 FOR UPDATE", scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			_, e := kms.LoadProtectedLocalOperations(ctx, scope, shortKeySource{source}, ledger, time.Now)
			done <- e
		}()
		deadline := time.Now().Add(time.Second)
		blocked := false
		for time.Now().Before(deadline) {
			var n int
			e = sqlAdmin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename='local_keys_runtime' AND wait_event_type='Lock'").Scan(&n)
			if e != nil {
				t.Fatal(e)
			}
			if n > 0 {
				blocked = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("lifecycle reader never reached held lock")
		}
		time.Sleep(450 * time.Millisecond)
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e == nil {
			t.Fatal("expired source renewed after lock")
		}
	})
	t.Run("recovery-blocked", func(t *testing.T) {
		if _, e = sqlAdmin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		if _, e = current.CurrentKeyConfiguration(ctx, scope, epoch); e == nil {
			t.Fatal("key use during blocked recovery")
		}
		if _, e = sqlAdmin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		if _, err := replaceSyntheticFleetObservationAfterActivation(ctx, sqlAdmin, scope.InstallationID); err != nil {
			t.Fatal(err)
		}
	})
	for _, statement := range []string{"DELETE FROM local_key_version", "UPDATE local_key_version SET fingerprint=decode(repeat('01',32),'hex')", "DELETE FROM local_key_configuration", "UPDATE fleet_trust SET recovery_blocked=false"} {
		if _, e = pool.Exec(ctx, statement); e == nil {
			t.Fatal("runtime changed protected history or recovery")
		}
	}
	if e = admin.CoreV1().Secrets(ns.Name).Delete(ctx, secondSecret.Name, meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	limit := time.Now().Add(5 * time.Second)
	for {
		_, e = current.CurrentKeyConfiguration(ctx, scope, epoch)
		if e != nil {
			break
		}
		if !time.Now().Before(limit) {
			t.Fatal("deleted Secret outlived original five-second observation")
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = secret("roots-v2", "artifact", 2, []int{1, 2}, materials[:2])
	if _, e = load(); e == nil {
		t.Fatal("same-name replacement bypassed pinned Secret UID")
	}
	if e = admin.CoreV1().ConfigMaps(ns.Name).Delete(ctx, object.Name, meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = current.CurrentKeyConfiguration(ctx, scope, epoch); e == nil {
		t.Fatal("deleted configuration retained authority")
	}
	t.Log("real Kubernetes named RBAC, immutable Secret pins, SQL rotation history, mTLS wrap/unwrap, old-process fencing, retained-key reads, rollback/suspension, lock expiry and recovery denial passed; operation approvals remain synthetic")
}
