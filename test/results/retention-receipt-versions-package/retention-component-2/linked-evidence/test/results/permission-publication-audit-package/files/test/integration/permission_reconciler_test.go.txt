package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Real API/admission/watch + PostgreSQL + encrypted S3 composition. The test
// deliberately keeps key custody synthetic; no production IdP/collector exists.
func testGuardedReconciliation(t *testing.T, ctx context.Context, c *rest.Config, reader *kube.PermissionClient, guard *kube.PermissionGuard, plan cfg.PermissionAdministration, dsn, s3endpoint, readerToken string) {
	t.Helper()
	cluster := plan.Delegations[0].Scope.ClusterID
	control := plan.ControlNamespace
	native, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	actor := rest.CopyConfig(c)
	actor.Impersonate = rest.ImpersonationConfig{UserName: "fixture-delegate", Groups: []string{"asservat-fixture-writers", "system:authenticated"}}
	api, err := dynamic.NewForConfig(actor)
	if err != nil {
		t.Fatal(err)
	}
	targetNS := plan.Delegations[0].Scope.Namespace
	resource := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}
	binding := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "reconciled-owners", "namespace": control.Name}, "spec": map[string]any{"effect": "Allow", "subjects": []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "original-owner"}}, "roles": []any{"workload-maintainer"}, "scope": map[string]any{"clusterID": cluster, "namespaceRef": map[string]any{"name": targetNS.Name, "uid": targetNS.UID}}, "reason": "synthetic reconciliation"}}}
	binding, err = api.Resource(resource).Namespace(control.Name).Create(ctx, binding, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The automation path uses an administrator-authored second binding. Keep
	// the original delegate-owned binding for the independent continuity tests.
	adminConfig := rest.CopyConfig(c)
	adminConfig.Impersonate = rest.ImpersonationConfig{UserName: "fixture-admin", Groups: []string{"asservat-fixture-writers", "system:authenticated"}}
	adminAPI, err := dynamic.NewForConfig(adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	automationBinding := binding.DeepCopy()
	automationBinding.SetName("reconciled-automation")
	automationBinding.SetUID("")
	automationBinding.SetResourceVersion("")
	automationBinding.SetGeneration(0)
	automationBinding.SetManagedFields(nil)
	_ = unstructured.SetNestedSlice(automationBinding.Object, []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": "automation-team"}}, "spec", "subjects")
	_ = unstructured.SetNestedMap(automationBinding.Object, map[string]any{"allowedActions": []any{"logs"}, "maxLifetimeSeconds": int64(3600), "maxExecutions": int64(10), "maxBytes": int64(1000), "maxObservedBytes": int64(0)}, "spec", "automation")
	automationBinding, err = adminAPI.Resource(resource).Namespace(control.Name).Create(ctx, automationBinding, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.PermissionSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := configapp.InitialBindingDigest(snapshot)
	now := time.Now().UTC()
	review, err := native.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "permission-bootstrap"}, Data: map[string]string{"format": "asservat-permission-bootstrap/v1", "reviewer": "fixture-admin", "bindingsSHA256": hex.EncodeToString(digest[:]), "reviewedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(time.Hour).Format(time.RFC3339Nano)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	delegatedNative, err := kubernetes.NewForConfig(actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = delegatedNative.CoreV1().ConfigMaps(control.Name).Patch(ctx, review.Name, types.MergePatchType, []byte(`{"data":{"reviewer":"forged"}}`), meta.PatchOptions{}); !apierrors.IsForbidden(err) {
		t.Fatalf("delegate can alter bootstrap: %v", err)
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
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 8
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
	bucket := "reconciler-audit"
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
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	reconciler := configapp.BindingReconciler{RootID: root, Reader: reader, Watcher: reader, Trust: guard, Review: reviewReader, Store: store, Now: time.Now, NewID: custodyID}
	go func() { done <- reconciler.Run(runCtx) }()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Error("reconciler did not terminate")
			}
		}
	}()
	target := authorization.Target{ClusterID: cluster, NamespaceUID: targetNS.UID, WorkloadUID: custodyID(), PodUID: custodyID()}
	wait := func(check func() bool) {
		t.Helper()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			if check() {
				return
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("reconciler stopped: %v", err)
			case <-timer.C:
				t.Fatal("reconciliation timed out")
			case <-tick.C:
			}
		}
	}
	wait(func() bool { p, e := store.Permissions(ctx, target); return e == nil && p.DeniesComplete })
	if p, e := store.Permissions(ctx, target); e != nil || len(p.Allows) != 0 {
		t.Fatalf("allows activated before audit: %v", e)
	}
	publish := func() {
		t.Helper()
		if err := (auditapp.AuthorityPublisher{Ledger: store, Objects: writer}).PublishAuthority(ctx); err != nil {
			t.Fatal(err)
		}
	}
	current := func(subject string) string {
		p, e := store.Permissions(ctx, target)
		if e != nil {
			return ""
		}
		for _, a := range p.Allows {
			if a.Audience.BasisUID == string(binding.GetUID()) && a.Audience.SubjectID == subject {
				return a.Audience.AssignmentID
			}
		}
		return ""
	}
	var original string
	wait(func() bool { publish(); original = current("original-owner"); return original != "" })
	// Real native admission -> bounded reader -> journal -> SQL -> encrypted
	// audit -> current automation projection, without a directory credential.
	installation := custodyID()
	automationReader, err := postgres.NewAutomationAuthorities(ctx, pool, root, installation)
	if err != nil {
		t.Fatal(err)
	}
	var delegation identity.Revision
	for _, b := range snapshot.Bindings {
		if b.Resource.UID == string(automationBinding.GetUID()) {
			delegation = identity.Revision{UID: b.Resource.UID, Generation: b.Resource.Generation, Digest: b.Resource.SpecDigest}
		}
	}
	wait(func() bool {
		publish()
		permissions, e := store.Permissions(ctx, target)
		if e != nil {
			return false
		}
		var owners []artifact.AudienceAssignment
		for _, a := range permissions.Allows {
			if a.Audience.BasisUID == delegation.UID && a.Audience.SubjectID == "automation-team" {
				owners = append(owners, a.Audience)
			}
		}
		now := time.Now().UTC()
		accepted := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: "synthetic-policy", Creator: identity.Principal{Issuer: "https://id.example.invalid", Subject: "synthetic-author", ClientID: "console", Kind: identity.Human}, Executor: authorization.PolicyPrincipal(installation, "synthetic-policy"), ScopeDigest: artifact.Digest{11}, ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: delegation, Owners: owners, Actions: []string{"logs"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 1000}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
		current, e := automationReader.PolicyAutomationAuthority(ctx, accepted, target)
		return e == nil && current.Envelope.MaxBytes == 1000 && authorization.EvaluatePolicy(accepted, current, authorization.PolicyUse{PolicyUID: accepted.PolicyUID, ScopeDigest: accepted.ScopeDigest, Target: target, Purpose: authorization.PolicyIncident}, time.Now()).Eligible
	})
	if _, err = api.Resource(resource).Namespace(control.Name).Patch(ctx, binding.GetName(), types.MergePatchType, []byte(`{"metadata":{"labels":{"fixture":"metadata-only"}}}`), meta.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	// Both writes complete before waiting for SQL; final-state polling alone would
	// miss the intermediate owner's retirement.
	for _, subject := range []string{"temporary-owner", "original-owner"} {
		live, e := api.Resource(resource).Namespace(control.Name).Get(ctx, binding.GetName(), meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_ = unstructured.SetNestedSlice(live.Object, []any{map[string]any{"kind": "Group", "issuer": "https://id.example.invalid", "id": subject}}, "spec", "subjects")
		if _, e = api.Resource(resource).Namespace(control.Name).Update(ctx, live, meta.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	wait(func() bool { publish(); id := current("original-owner"); return id != "" && id != original })
	var transitions int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE stream_id=$1 AND subject_id='temporary-owner' AND retired_at IS NOT NULL", root).Scan(&transitions); err != nil || transitions != 1 {
		t.Fatalf("intermediate owner lost: %d %v", transitions, err)
	}
	// Stay beyond a finite watch interval while the complete LIST heartbeat keeps
	// the permission decision current. No review renewal is needed.
	until := time.NewTimer(5 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	waiting := true
	for waiting {
		select {
		case <-until.C:
			waiting = false
		case <-tick.C:
			publish()
		case err := <-done:
			stopped = true
			t.Fatalf("watch renewal stopped: %v", err)
		}
	}
	tick.Stop()
	until.Stop()
	if current("original-owner") == "" {
		t.Fatal("continuous observation lost eligibility")
	}
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	stopped = true
	if _, err = store.Permissions(ctx, target); !errors.Is(err, cfg.ErrUnavailable) {
		t.Fatalf("stopped controller still authoritative: %v", err)
	}
	testPolicySourceObservation(t, ctx, c, cluster, control, targetNS, readerToken, dsn, root, installation)
}
