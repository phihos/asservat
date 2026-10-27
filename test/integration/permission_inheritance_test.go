package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ADR-242: a real namespaceMetadata PermissionSource reconciled from a real
// API server's namespace LIST/watch into PostgreSQL with encrypted audit.
// The guard, review and KMS boundaries are the same synthetic fixtures as the
// explicit-binding reconciliation; nothing here enables collection.
func testInheritedReconciliation(t *testing.T, c *rest.Config, reader *kube.PermissionClient, guard *kube.PermissionGuard, plan cfg.PermissionAdministration, dsn, s3endpoint string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cluster := plan.Delegations[0].Scope.ClusterID
	control := plan.ControlNamespace
	issuer := "https://id.example.invalid"
	native, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig := rest.CopyConfig(c)
	adminConfig.Impersonate = rest.ImpersonationConfig{UserName: "fixture-admin", Groups: []string{"asservat-fixture-writers", "system:authenticated"}}
	admin, err := dynamic.NewForConfig(adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := native.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "inherit-payments", Labels: map[string]string{"inherit.example.invalid/managed": "true", "unrelated": "v1"}, Annotations: map[string]string{"inherit.example.invalid/owner": "payments"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Selected but differently owned, and owned but outside the selector.
	for name, labels := range map[string]map[string]string{"inherit-payroll": {"inherit.example.invalid/managed": "true"}, "inherit-unmanaged": {}} {
		owner := "payroll"
		if name == "inherit-unmanaged" {
			owner = "payments"
		}
		if _, err = native.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: labels, Annotations: map[string]string{"inherit.example.invalid/owner": owner}}}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	sources := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "permissionsources"}
	bindings := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
	source := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "inherited-owners", "namespace": control.Name},
		"spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"inherit.example.invalid/managed": "true"}}, "excludedNamespaces": []any{"kube-system"},
			"role": "workload-maintainer", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "administratorManaged", "reviewRef": "synthetic-platform-attestation"},
			"metadataMapping": map[string]any{"field": "annotation", "key": "inherit.example.invalid/owner", "mode": "valueMap", "issuer": issuer, "values": map[string]any{"payments": []any{"team-inherited"}}}}}}
	if source, err = admin.Resource(sources).Namespace(control.Name).Create(ctx, source, meta.CreateOptions{FieldValidation: "Strict"}); err != nil {
		t.Fatal(err)
	}
	explicit := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "inherit-explicit", "namespace": control.Name},
		"spec": map[string]any{"effect": "Allow", "subjects": []any{map[string]any{"kind": "Group", "issuer": issuer, "id": "team-explicit"}}, "roles": []any{"evidence-reader"}, "scope": map[string]any{"clusterID": cluster, "namespaceRef": map[string]any{"name": ns.Name, "uid": string(ns.UID)}}, "reason": "synthetic inheritance"}}}
	if _, err = admin.Resource(bindings).Namespace(control.Name).Create(ctx, explicit, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.PermissionSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := configapp.InitialBindingDigest(snapshot)
	now := time.Now().UTC()
	review, err := native.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "permission-bootstrap-inheritance"}, Data: map[string]string{"format": "asservat-permission-bootstrap/v1", "reviewer": "fixture-admin", "bindingsSHA256": hex.EncodeToString(digest[:]), "reviewedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(time.Hour).Format(time.RFC3339Nano)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reviewReader, err := kube.NewBootstrapReviewClient(reader, review.Name, string(review.UID))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, u.Host)
	pc, err := pgxpool.ParseConfig("postgres://authority_runtime:synthetic-authority@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = tlsConfig, nil, 8
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	root := custodyID()
	store, err := postgres.NewPermissions(ctx, pool, root)
	if err != nil {
		t.Fatal(err)
	}
	bridge := tlsBridge(t, s3endpoint)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3api := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	bucket := "inheritance-audit"
	if _, err = s3api.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = s3api.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{aead}
	writer := &objectstore.AuthorityObjects{Store: objects, Seal: keys, Open: keys}
	namespaces, err := kube.NewPermissionClient(c, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// A reader without namespace list/watch rights: inheritance unavailable.
	denied := rest.CopyConfig(c)
	denied.Impersonate = rest.ImpersonationConfig{UserName: "fixture-outsider", Groups: []string{"system:authenticated"}}
	blind, err := kube.NewPermissionClient(denied, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var done chan error
	var stop context.CancelFunc
	start := func(observer configapp.NamespaceObserver) {
		t.Helper()
		run, cancel := context.WithCancel(ctx)
		stop, done = cancel, make(chan error, 1)
		r := configapp.BindingReconciler{RootID: root, Reader: reader, Watcher: reader, Trust: guard, Review: reviewReader, Store: store, Namespaces: observer, NamespaceClusterID: cluster, Now: time.Now, NewID: custodyID}
		go func() { done <- r.Run(run) }()
	}
	halt := func() {
		t.Helper()
		stop()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("reconciler did not terminate")
		}
	}
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	target := authorization.Target{ClusterID: cluster, NamespaceUID: string(ns.UID), WorkloadUID: custodyID(), PodUID: custodyID()}
	publish := func() {
		t.Helper()
		if err := (auditapp.AuthorityPublisher{Ledger: store, Objects: writer}).PublishAuthority(ctx); err != nil {
			t.Fatal(err)
		}
	}
	assignment := func(subject string) string {
		p, e := store.Permissions(ctx, target)
		if e != nil {
			return ""
		}
		for _, a := range p.Allows {
			if a.Audience.SubjectID == subject {
				return a.Audience.AssignmentID
			}
		}
		return ""
	}
	wait := func(what string, check func() bool) {
		t.Helper()
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			publish()
			if check() {
				return
			}
			select {
			case err := <-done:
				t.Fatalf("reconciler stopped while waiting for %s: %v", what, err)
			case <-timer.C:
				t.Fatalf("timed out waiting for %s", what)
			case <-tick.C:
			}
		}
	}
	retired := func(id string) bool {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE id=$1 AND retired_at IS NOT NULL", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	patchNamespace := func(name, patch string) {
		t.Helper()
		if _, err := native.CoreV1().Namespaces().Patch(ctx, name, types.MergePatchType, []byte(patch), meta.PatchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	start(namespaces)
	// Inheritance grants the mapped group only in the selected, mapped
	// namespace, beside an independent explicit binding.
	var first string
	wait("inherited grant", func() bool {
		first = assignment("team-inherited")
		return first != "" && assignment("team-explicit") != ""
	})
	for _, name := range []string{"inherit-payroll", "inherit-unmanaged"} {
		other, err := native.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := store.Permissions(ctx, authorization.Target{ClusterID: cluster, NamespaceUID: string(other.UID), WorkloadUID: custodyID(), PodUID: custodyID()})
		if err != nil || len(p.Allows) != 0 {
			t.Fatalf("%s gained inherited access: %v %+v", name, err, p.Allows)
		}
	}
	// An unrelated namespace label write keeps the identity (continuous watch).
	patchNamespace(ns.Name, `{"metadata":{"labels":{"unrelated":"v2"}}}`)
	time.Sleep(2 * time.Second)
	if id := assignment("team-inherited"); id != first {
		t.Fatalf("unrelated namespace write changed the assignment: %q", id)
	}
	// A -> B -> A ownership written back to back retires the first owner's
	// assignment, even though the final value matches.
	patchNamespace(ns.Name, `{"metadata":{"annotations":{"inherit.example.invalid/owner":"payroll"}}}`)
	patchNamespace(ns.Name, `{"metadata":{"annotations":{"inherit.example.invalid/owner":"payments"}}}`)
	var second string
	wait("A-B-A re-grant", func() bool { second = assignment("team-inherited"); return second != "" && second != first })
	if !retired(first) {
		t.Fatal("intermediate owner change did not retire the assignment")
	}
	// An explicit deny overrides the inherited allow.
	deny := explicit.DeepCopy()
	deny.SetName("inherit-deny")
	_ = unstructured.SetNestedField(deny.Object, "Deny", "spec", "effect")
	_ = unstructured.SetNestedSlice(deny.Object, []any{map[string]any{"kind": "Group", "issuer": issuer, "id": "team-inherited"}}, "spec", "subjects")
	_ = unstructured.SetNestedSlice(deny.Object, []any{"workload-maintainer"}, "spec", "roles")
	if _, err = admin.Resource(bindings).Namespace(control.Name).Create(ctx, deny, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	member := func() authorization.Result {
		now := time.Now()
		i := identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: "member", ClientID: "console", Kind: identity.Human}, Groups: []string{"team-inherited"}, Scopes: []string{"evidence:capture", "evidence:read"}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		p, e := store.Permissions(ctx, target)
		if e != nil {
			return authorization.Result{Reason: "PermissionUnavailable"}
		}
		return authorization.ScopeEligibility(i, p, authorization.CollectContext, target, now)
	}
	wait("explicit deny", func() bool { return member().Reason == "ExplicitDeny" })
	if err = admin.Resource(bindings).Namespace(control.Name).Delete(ctx, "inherit-deny", meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("deny removal", func() bool { return member().Eligible })
	// A complete relist by a restarted reconciler (new epoch) keeps the
	// identity: the namespace resourceVersion is unchanged.
	halt()
	start(namespaces)
	wait("restart relist", func() bool { return assignment("team-inherited") == second })
	// A namespace observer that cannot list namespaces leaves the source
	// unavailable: the inherited allow stops, its assignment is kept, and the
	// explicit binding is unaffected.
	halt()
	start(blind)
	wait("unavailable source", func() bool { return assignment("team-explicit") != "" && assignment("team-inherited") == "" })
	if retired(second) {
		t.Fatal("unavailable source retired its assignment")
	}
	halt()
	start(namespaces)
	wait("recovered source", func() bool { return assignment("team-inherited") == second })
	// Removing the ownership annotation revokes; restoring it is a new grant.
	patchNamespace(ns.Name, `{"metadata":{"annotations":{"inherit.example.invalid/owner":null}}}`)
	wait("revocation", func() bool { return assignment("team-inherited") == "" && retired(second) })
	patchNamespace(ns.Name, `{"metadata":{"annotations":{"inherit.example.invalid/owner":"payments"}}}`)
	wait("re-grant", func() bool { id := assignment("team-inherited"); return id != "" && id != second && id != first })
	// Disabling the source retires; the explicit binding stays.
	_ = unstructured.SetNestedField(source.Object, false, "spec", "enabled")
	live, err := admin.Resource(sources).Namespace(control.Name).Get(ctx, source.GetName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(live.Object, false, "spec", "enabled")
	if _, err = admin.Resource(sources).Namespace(control.Name).Update(ctx, live, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("disabled source", func() bool { return assignment("team-inherited") == "" && assignment("team-explicit") != "" })
	halt()
	for _, name := range []string{"inherit-payments", "inherit-payroll", "inherit-unmanaged"} {
		_ = native.CoreV1().Namespaces().Delete(ctx, name, meta.DeleteOptions{})
	}
	_ = admin.Resource(sources).Namespace(control.Name).Delete(ctx, source.GetName(), meta.DeleteOptions{})
	_ = admin.Resource(bindings).Namespace(control.Name).Delete(ctx, "inherit-explicit", meta.DeleteOptions{})
}
