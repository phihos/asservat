package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// realNamespaceGuard adapts a real capacity namespace guard to the
// reconciler's guard port, as the hub-worker's shared guards do (ADR-247).
type realNamespaceGuard struct{ guard *kube.CapacityNamespaceGuard }

func (g realNamespaceGuard) NamespaceGuard(ctx context.Context, cluster string) (cfg.NamespaceGuardProof, error) {
	p, err := g.guard.CapacityNamespaceProtection(ctx)
	if err != nil || p.ClusterID != cluster {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	return cfg.NamespaceGuardProof{ClusterID: cluster, Name: "namespace-guard", LabelKeys: slices.Clone(p.Keys), ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, nil
}

// realDirectory adapts a real identity settings reader to the group
// directory port, as the hub-worker's identity directory does (ADR-247).
type realDirectory struct{ settings *kube.IdentityPolicyClient }

func (d realDirectory) GroupDirectory(ctx context.Context, issuer string) (cfg.GroupDirectory, error) {
	p, err := d.settings.IdentityPolicy(ctx, issuer)
	if err != nil {
		return cfg.GroupDirectory{}, err
	}
	return cfg.GroupDirectory{Issuer: issuer, Groups: slices.Clone(p.EligibleGroups), ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, nil
}

// ADR-247: an admissionEnforced namespaceMetadata source under a real
// namespace label guard (live dry-run proof) and a groupID source validated
// against real identity settings' eligibleGroups, reconciled from real
// namespaces into PostgreSQL with encrypted audit.
func testGuardedAndGroupInheritance(t *testing.T, c *rest.Config, reader *kube.PermissionClient, trust *kube.PermissionGuard, plan cfg.PermissionAdministration, dsn, s3endpoint string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cluster, control := plan.Delegations[0].Scope.ClusterID, plan.ControlNamespace
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
	// The guard administrator writes namespaces; RBAC is not under test here.
	nsAdmin := rest.CopyConfig(c)
	nsAdmin.Impersonate = rest.ImpersonationConfig{UserName: "fixture-admin", Groups: []string{"system:masters", "system:authenticated"}}
	adminNative, err := kubernetes.NewForConfig(nsAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// Two namespaces: one guarded by labels, one owned by a group ID.
	guardedNS, err := adminNative.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "guarded-payments", Labels: map[string]string{"guarded.example.invalid/managed": "true", "guarded.example.invalid/owner": "payments"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	groupNS, err := adminNative.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "group-owned", Labels: map[string]string{"group.example.invalid/managed": "true"}, Annotations: map[string]string{"group.example.invalid/owner-group": "platform-developers"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The installation's namespace label guard and its unprivileged probe.
	if _, err = native.CoreV1().ServiceAccounts(control.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "namespace-guard-probe"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	probeAccount, err := native.CoreV1().ServiceAccounts(control.Name).Get(ctx, "namespace-guard-probe", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "namespace-guard-probe"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{control.Name}, Verbs: []string{"get", "update"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "namespace-guard-probe"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "namespace-guard-probe", Namespace: control.Name}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "namespace-guard-probe"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	keys := []string{"guarded.example.invalid/managed", "guarded.example.invalid/owner"}
	guardPlan := cfg.CapacityNamespaceAdministration{Name: "guarded-namespace-labels", Administrators: plan.Administrators, Keys: keys, ProbeNamespace: control, ProbeAccount: cfg.NamespaceRef{Name: probeAccount.Name, UID: string(probeAccount.UID)}}
	policy, binding, err := kube.CapacityNamespaceAdmission(guardPlan)
	if err != nil {
		t.Fatal(err)
	}
	if policy, err = native.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if binding, err = native.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	expiry := int64(600)
	token, err := native.CoreV1().ServiceAccounts(control.Name).CreateToken(ctx, probeAccount.Name, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiry}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	probeConfig := rest.AnonymousClientConfig(c)
	probeConfig.BearerToken = token.Status.Token
	probe, err := kube.NewPermissionClient(probeConfig, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := kube.NewPermissionClient(c, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	namespaceGuard, err := kube.NewCapacityNamespaceGuard(observer, probe, guardPlan, kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion})
	if err != nil {
		t.Fatal(err)
	}
	guards := realNamespaceGuard{namespaceGuard}
	proven := false
	for range 100 {
		if _, err = guards.NamespaceGuard(ctx, cluster); err == nil {
			proven = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !proven {
		t.Fatal("namespace guard never proved enforcement", err)
	}
	// An unprivileged label write to a guarded key is denied by the guard.
	outsider := rest.CopyConfig(c)
	outsider.Impersonate = rest.ImpersonationConfig{UserName: "fixture-outsider", Groups: []string{"system:authenticated", "system:masters"}}
	outsiderNative, err := kubernetes.NewForConfig(outsider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = outsiderNative.CoreV1().Namespaces().Patch(ctx, guardedNS.Name, types.MergePatchType, []byte(`{"metadata":{"labels":{"guarded.example.invalid/owner":"payroll"}}}`), meta.PatchOptions{}); err == nil || !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "forbidden") && !strings.Contains(err.Error(), "Forbidden") {
		t.Fatal("unprivileged write of a guarded key was not denied", err)
	}
	// Identity settings: the configured group directory.
	settings, err := json.Marshal(contracts.IdentitySettings{SchemaVersion: "identity-settings/v1", Revision: 1, Issuer: issuer, Clients: []contracts.IdentityClient{{ID: "asservat-console", Kind: "human", ClassQualified: true}},
		EligibleSubjects: []contracts.IdentitySubject{}, EligibleGroups: []string{"platform-developers"}, GroupsAtIssueQualified: true, GroupMaxAgeSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	identityMap, err := native.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "group-directory-identity"}, Data: map[string]string{"identity.json": string(settings)}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identityReader, err := kube.NewIdentityPolicyClient(observer, identityMap.Name, string(identityMap.UID), issuer)
	if err != nil {
		t.Fatal(err)
	}
	// ADR-247: the workload metadata guard, two Deployments and a source.
	wl := newWorkloadFixture(t, ctx, c, native, adminNative, plan.Administrators, cluster, control, issuer)
	defer wl.cleanup()
	// The two sources.
	sources := schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "permissionsources"}
	guardedSource := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "guarded-owners", "namespace": control.Name},
		"spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"guarded.example.invalid/managed": "true"}}, "excludedNamespaces": []any{"kube-system"},
			"role": "workload-maintainer", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "admissionEnforced", "reviewRef": "synthetic-guard-review", "guardRef": "namespace-guard"},
			"metadataMapping": map[string]any{"field": "label", "key": "guarded.example.invalid/owner", "mode": "valueMap", "issuer": issuer, "values": map[string]any{"payments": []any{"team-guarded"}}}}}}
	groupSource := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "PermissionSource", "metadata": map[string]any{"name": "group-owners", "namespace": control.Name},
		"spec": map[string]any{"enabled": true, "clusterID": cluster, "type": "namespaceMetadata", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"group.example.invalid/managed": "true"}}, "excludedNamespaces": []any{"kube-system"},
			"role": "evidence-reader", "maxDecisionAgeSeconds": int64(30), "maxNamespaces": int64(100), "protection": map[string]any{"mode": "administratorManaged", "reviewRef": "synthetic-provisioner-attestation"},
			"metadataMapping": map[string]any{"field": "annotation", "key": "group.example.invalid/owner-group", "mode": "groupID", "issuer": issuer}}}}
	for _, s := range []*unstructured.Unstructured{guardedSource, groupSource, wl.source} {
		if _, err = admin.Resource(sources).Namespace(control.Name).Create(ctx, s, meta.CreateOptions{FieldValidation: "Strict"}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := reader.PermissionSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := configapp.InitialBindingDigest(snapshot)
	now := time.Now().UTC()
	review, err := native.CoreV1().ConfigMaps(control.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "permission-bootstrap-guarded"}, Data: map[string]string{"format": "asservat-permission-bootstrap/v1", "reviewer": "fixture-admin", "bindingsSHA256": hex.EncodeToString(digest[:]), "reviewedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(time.Hour).Format(time.RFC3339Nano)}}, meta.CreateOptions{})
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
	bucket := "guarded-audit"
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
	writer := &objectstore.AuthorityObjects{Store: objects, Seal: authorityTestKeys{aead}, Open: authorityTestKeys{aead}}
	namespaces, err := kube.NewPermissionClient(c, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var done chan error
	var stop context.CancelFunc
	start := func(g configapp.NamespaceGuardReader) {
		t.Helper()
		run, cancel := context.WithCancel(ctx)
		stop, done = cancel, make(chan error, 1)
		r := configapp.BindingReconciler{RootID: root, Reader: reader, Watcher: reader, Trust: trust, Review: reviewReader, Store: store, Namespaces: namespaces, NamespaceClusterID: cluster, Guards: g, Directory: realDirectory{identityReader}, Workloads: journalWorkloads{wl.journal}, WorkloadGuards: wl.guard, Now: time.Now, NewID: custodyID}
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
	assignment := func(ns *core.Namespace, subject string) string {
		p, e := store.Permissions(ctx, authorization.Target{ClusterID: cluster, NamespaceUID: string(ns.UID), WorkloadUID: custodyID(), PodUID: custodyID()})
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
	workloadAssignment := func(w *apps.Deployment, subject string) string {
		p, e := store.Permissions(ctx, authorization.Target{ClusterID: cluster, NamespaceUID: string(wl.namespace.UID), WorkloadUID: string(w.UID), PodUID: custodyID()})
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
		timer := time.NewTimer(20 * time.Second)
		defer timer.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			if err := (auditapp.AuthorityPublisher{Ledger: store, Objects: writer}).PublishAuthority(ctx); err != nil {
				t.Fatal(err)
			}
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
	start(guards)
	var guardedID string
	wait("guarded and group grants", func() bool {
		guardedID = assignment(guardedNS, "team-guarded")
		return guardedID != "" && assignment(groupNS, "platform-developers") != ""
	})
	// REQ-PER-005: the workload source grants its group on exactly the
	// owned workload's UID, not on the other workload of the namespace.
	var workloadID string
	wait("workload grant", func() bool { workloadID = workloadAssignment(wl.api, "team-workload"); return workloadID != "" })
	if workloadAssignment(wl.web, "team-workload") != "" {
		t.Fatal("workload grant reached another workload of the namespace")
	}
	// An unrelated workload write keeps the assignment: its journal version
	// changes only with an observed value.
	if _, err = adminNative.AppsV1().Deployments(wl.namespace.Name).Patch(ctx, "api", types.MergePatchType, []byte(`{"metadata":{"annotations":{"unrelated.example.invalid/note":"x"}},"spec":{"replicas":0}}`), meta.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(configapp.RemoteNamespaceRefresh + 2*time.Second)
	if got := workloadAssignment(wl.api, "team-workload"); got != workloadID {
		t.Fatal("unrelated workload write re-minted the assignment", got, workloadID)
	}
	// A -> B -> A of the owner label is never skipped: a new assignment.
	for _, owner := range []string{"other", "payments"} {
		if _, err = adminNative.AppsV1().Deployments(wl.namespace.Name).Patch(ctx, "api", types.MergePatchType, []byte(`{"metadata":{"labels":{"`+workloadOwner+`":"`+owner+`"}}}`), meta.PatchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	wait("workload A -> B -> A re-minted", func() bool {
		got := workloadAssignment(wl.api, "team-workload")
		return got != "" && got != workloadID
	})
	// A group ID outside the configured directory grants nothing.
	if _, err = adminNative.CoreV1().Namespaces().Patch(ctx, groupNS.Name, types.MergePatchType, []byte(`{"metadata":{"annotations":{"group.example.invalid/owner-group":"cluster-admins"}}}`), meta.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("unknown group revoked", func() bool {
		return assignment(groupNS, "platform-developers") == "" && assignment(groupNS, "cluster-admins") == ""
	})
	// Without a current guard proof the guarded source stops granting but
	// keeps its assignment; the proof returning restores the same identity.
	halt()
	start(nil)
	wait("guard unavailable", func() bool { return assignment(guardedNS, "team-guarded") == "" })
	var retired int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM permission_assignment WHERE id=$1 AND retired_at IS NOT NULL", guardedID).Scan(&retired); err != nil || retired != 0 {
		t.Fatal("unavailable guard retired the assignment", retired, err)
	}
	halt()
	start(guards)
	wait("guard restored", func() bool { return assignment(guardedNS, "team-guarded") == guardedID })
	// Removing the guard binding ends the live proof: the source stops.
	if err = native.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("guard removed", func() bool { return assignment(guardedNS, "team-guarded") == "" })
	halt()
	_ = native.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(ctx, policy.Name, meta.DeleteOptions{})
	for _, name := range []string{guardedNS.Name, groupNS.Name} {
		_ = native.CoreV1().Namespaces().Delete(ctx, name, meta.DeleteOptions{})
	}
	for _, s := range []string{"guarded-owners", "group-owners", "workload-owners"} {
		_ = admin.Resource(sources).Namespace(control.Name).Delete(ctx, s, meta.DeleteOptions{})
	}
}
