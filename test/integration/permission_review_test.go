package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	authenticationv1 "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ADR-245 (REQ-PER-004): real SubjectAccessReviews by a connector account
// with only review/read rights, for a mapped OIDC user, against a real API
// server's RBAC authorizer, recorded in real PostgreSQL under an accepted
// kubernetesExec source with encrypted authority audit. The hub-to-region
// query transport is not exercised here; the region adapter is called
// directly with the same request the transport carries.
func testDecisionTimeReviews(t *testing.T, c *rest.Config, dsn, s3endpoint string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	native, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	cluster := custodyID()
	issuer := "https://id.example.invalid"
	ns, err := native.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "review-payments", Labels: map[string]string{"review.example.invalid/managed": "true"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod := func(name string) *core.Pod {
		no, yes, user := false, true, int64(65532)
		p, err := native.CoreV1().Pods(ns.Name).Create(ctx, &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: core.PodSpec{AutomountServiceAccountToken: &no,
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &user, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers:      []core.Container{{Name: "app", Image: "registry.k8s.io/pause:3.10", SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := pod("api-a"), pod("api-b")
	// The connector account: review create and the target reads, nothing else.
	if _, err = native.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "connector"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "review-connector"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"subjectaccessreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"namespaces", "pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "review-connector"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "connector", Namespace: ns.Name}},
		RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "review-connector"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A second account with the reads but no review right: SAR unavailable.
	if _, err = native.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "blind"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "review-blind"}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: "blind", Namespace: ns.Name}},
		RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "view"}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	connector := func(account string) *kube.PodTargets {
		t.Helper()
		expiry := int64(600)
		token, err := native.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, account, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiry}}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		config := rest.AnonymousClientConfig(c)
		config.BearerToken = token.Status.Token
		client, err := kube.NewPermissionClient(config, cluster, cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		targets, err := kube.NewAPIContextTargets(client)
		if err != nil {
			t.Fatal(err)
		}
		groups := "oidc:"
		if targets, err = targets.WithIdentityMappings([]contracts.RegionalIdentityMapping{{Name: "company", Issuer: issuer, UsernamePrefix: "oidc:", GroupsPrefix: &groups}}); err != nil {
			t.Fatal(err)
		}
		return targets
	}
	reviewer, blind := connector("connector"), connector("blind")
	// alice: create pods/exec on Pod A only; carol: the legacy get-only grant;
	// the group team-exec: create pods/exec on Pod A.
	if _, err = native.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "exec-a"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{a.Name}, Verbs: []string{"create"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = native.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "exec-get"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"get"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	bind := func(name, role string, subject rbac.Subject) {
		t.Helper()
		if _, err := native.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{subject}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role}}, meta.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	bind("alice-exec", "exec-a", rbac.Subject{Kind: "User", APIGroup: rbac.GroupName, Name: "oidc:alice"})
	bind("carol-get", "exec-get", rbac.Subject{Kind: "User", APIGroup: rbac.GroupName, Name: "oidc:carol"})
	bind("team-exec", "exec-a", rbac.Subject{Kind: "Group", APIGroup: rbac.GroupName, Name: "oidc:team-exec"})

	// Real SQL acceptance of the product-decoded kubernetesExec source.
	decoder, err := kube.NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(map[string]any{"enabled": true, "clusterID": cluster, "type": "kubernetesExec", "namespaceSelector": map[string]any{"matchLabels": map[string]any{"review.example.invalid/managed": "true"}},
		"excludedNamespaces": []any{"kube-system"}, "role": "workload-maintainer", "maxDecisionAgeSeconds": 30, "maxNamespaces": 10, "identityMappingRef": "company",
		"admissionParity": map[string]any{"mode": "noAdditionalRestrictions", "reviewRef": "synthetic-exec-attestation"}})
	decoded, err := decoder.DecodePermissionSourceSpec(specJSON)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Resource = cfg.Resource{Kind: "PermissionSource", UID: custodyID(), ResourceVersion: "exec-1", Generation: 1, SpecDigest: decoded.Resource.SpecDigest}
	sources := cfg.ReviewSources([]cfg.Source{decoded})
	if len(sources) != 1 {
		t.Fatal("decoded exec source not accepted")
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
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = tlsConfig, nil, 4
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	root, epoch := custodyID(), custodyID()
	store, err := postgres.NewPermissions(ctx, pool, root)
	if err != nil {
		t.Fatal(err)
	}
	reviews, err := postgres.NewAccessReviews(ctx, pool, root)
	if err != nil {
		t.Fatal(err)
	}
	bridge := tlsBridge(t, s3endpoint)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3api := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	bucket := "review-audit"
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
	trust := artifact.Digest{1}
	if _, err = store.BeginPermissions(ctx, root, epoch, trust); err != nil {
		t.Fatal(err)
	}
	var sequence int64
	acceptBatch := func(bases []cfg.PermissionBasis, initial bool) {
		t.Helper()
		n := time.Now().UTC().Truncate(time.Microsecond)
		b := cfg.PermissionBatch{RootID: root, Epoch: epoch, RequestID: custodyID(), ExpectedSequence: sequence, TrustDigest: trust, InputDigest: artifact.Digest{byte(len(bases)) + 1, byte(sequence) + 1, 7}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Bases: bases}
		if initial {
			b.Initial = &cfg.PermissionInitialization{ClusterID: cluster, Control: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, BindingsDigest: artifact.Digest{8}}
		} else {
			b.ReviewSources = sources
		}
		r, err := store.AcceptPermissions(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		sequence = r.Sequence
		for range 4 {
			if err = (auditapp.AuthorityPublisher{Ledger: store, Objects: writer}).PublishAuthority(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	acceptBatch(nil, true)
	acceptBatch(nil, false)
	access := authapp.AccessReviews{Store: reviews, Reviewer: reviewer, Now: time.Now}
	human := func(subject string, groups ...string) identity.Identity {
		now := time.Now()
		return identity.Identity{Principal: identity.Principal{Issuer: issuer, Subject: subject, ClientID: "console", Kind: identity.Human}, Groups: groups, Scopes: []string{"evidence:read", "evidence:capture"},
			Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(time.Minute)}
	}
	request := func(p *core.Pod) targets.Request {
		return targets.Request{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, Workload: cfg.WorkloadRef{Kind: "Pod", Name: p.Name, UID: string(p.UID)}, PodName: p.Name, PodUID: string(p.UID)}
	}
	target := func(p *core.Pod) authorization.Target {
		return authorization.Target{ClusterID: cluster, NamespaceUID: string(ns.UID), WorkloadUID: string(p.UID), PodUID: string(p.UID)}
	}
	capture := func(i identity.Identity, p *core.Pod) authorization.CaptureEligibility {
		t.Helper()
		projection, err := store.Permissions(ctx, target(p))
		if err != nil {
			t.Fatal(err)
		}
		return authorization.ContextEligibility(i, projection, target(p), time.Now())
	}
	alice := human("alice")
	started := time.Now()
	if err = access.ReviewResolved(ctx, alice, request(a)); err != nil {
		t.Fatal(err)
	}
	// One accepted source: namespace and Pod GETs, one SAR and one SQL record.
	t.Logf("first_review_ms=%d", time.Since(started).Milliseconds())
	started = time.Now()
	for range 20 {
		if err = access.ReviewResolved(ctx, alice, request(a)); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("review_mean_ms=%.1f", float64(time.Since(started).Microseconds())/20/1000)
	granted := capture(alice, a)
	if !granted.Eligible || len(granted.DefaultAudience) != 1 || granted.DefaultAudience[0].SubjectID != "alice" || granted.DefaultAudience[0].BasisUID != sources[0].Resource.UID {
		t.Fatalf("create pods/exec on Pod A did not grant alice there: %+v", granted)
	}
	assignment := granted.DefaultAudience[0]
	// Permission on one replica is not permission on another.
	if err = access.ReviewResolved(ctx, alice, request(b)); err != nil {
		t.Fatal(err)
	}
	if r := capture(alice, b); r.Eligible {
		t.Fatal("exec on Pod A authorized Pod B")
	}
	// A legacy get-only exec grant and an unmapped identity grant nothing.
	carol := human("carol")
	if err = access.ReviewResolved(ctx, carol, request(a)); err != nil || capture(carol, a).Eligible {
		t.Fatal("get pods/exec authorized collection", err)
	}
	// The group mapping: bob holds no user grant, only the mapped group.
	bob := human("bob", "team-exec")
	if err = access.ReviewResolved(ctx, bob, request(a)); err != nil || !capture(bob, a).Eligible {
		t.Fatal("mapped group grant not honored", err)
	}
	// Groups are the request's current ones, never stored: bob's next request
	// without the group is reviewed afresh and ends the earlier decision.
	if err = access.ReviewResolved(ctx, human("bob"), request(a)); err != nil || capture(human("bob"), a).Eligible {
		t.Fatal("group grant survived without the current group", err)
	}
	// The retained audience of alice's capture: a read re-reviews the
	// recorded Pod and stays allowed while RBAC still allows it.
	readable := func() bool {
		t.Helper()
		if err := access.ReviewRecorded(ctx, alice, target(a)); err != nil {
			t.Log("review error:", err)
		}
		projection, err := store.Permissions(ctx, target(a))
		if err != nil {
			t.Fatal(err)
		}
		e := authorization.Retained{ArtifactID: custodyID(), Target: target(a), DataClass: "metadata", ExpiresAt: time.Now().Add(time.Hour), Audience: []artifact.AudienceAssignment{assignment}}
		return authorization.Evaluate(alice, projection, authorization.ReadApproved, target(a), &e, time.Now()).Eligible
	}
	if !readable() {
		t.Fatal("recorded audience could not read its own capture")
	}
	// RBAC removal: the next read reviews afresh and loses access.
	if err = native.RbacV1().RoleBindings(ns.Name).Delete(ctx, "alice-exec", meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	lost := false
	for range 50 {
		if !readable() {
			lost = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !lost {
		t.Fatal("read stayed allowed after the exec grant was removed")
	}
	// Re-granted with the source unchanged, the same recorded assignment
	// reads again: the identity was never retired.
	bind("alice-exec", "exec-a", rbac.Subject{Kind: "User", APIGroup: rbac.GroupName, Name: "oidc:alice"})
	restored := false
	for range 50 {
		if readable() {
			restored = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !restored {
		t.Fatal("re-granted exec did not restore the recorded audience")
	}
	// An explicit deny of the user wins over the fresh review.
	deny := cfg.PermissionBasis{Resource: cfg.Resource{Kind: "AccessBinding", UID: custodyID(), Generation: 1, ResourceVersion: "deny-1", SpecDigest: artifact.Digest{3}}, Scope: cfg.Scope{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}},
		Effect: "Deny", Subjects: []cfg.Subject{{Kind: "User", Issuer: issuer, ID: "alice"}}, Roles: []string{"workload-maintainer"}}
	deny.ScopeDigest = configapp.PermissionScopeDigest(deny)
	acceptBatch([]cfg.PermissionBasis{deny}, false)
	if err = access.ReviewResolved(ctx, alice, request(a)); err != nil {
		t.Fatal(err)
	}
	if r := capture(alice, a); r.Eligible || r.Reason != "ExplicitDeny" {
		t.Fatalf("deny did not win over the review: %+v", r)
	}
	acceptBatch(nil, false)
	if err = access.ReviewResolved(ctx, alice, request(a)); err != nil || !capture(alice, a).Eligible {
		t.Fatal("allowed after the deny was removed", err)
	}
	// SAR unavailable (the connector lacks review create): fails closed and
	// ends the earlier positive decision.
	unavailable := authapp.AccessReviews{Store: reviews, Reviewer: blind, Now: time.Now}
	if err = unavailable.ReviewResolved(ctx, alice, request(a)); err == nil {
		t.Fatal("review without review authority reported success")
	}
	if capture(alice, a).Eligible {
		t.Fatal("SAR outage left the earlier decision current")
	}
	// A deleted Pod is reviewed by its recorded name; its read stays
	// available while the authorizer allows the name.
	if err = native.CoreV1().Pods(ns.Name).Delete(ctx, a.Name, meta.DeleteOptions{GracePeriodSeconds: new(int64)}); err != nil {
		t.Fatal(err)
	}
	gone := false
	for range 100 {
		if _, err := native.CoreV1().Pods(ns.Name).Get(ctx, a.Name, meta.GetOptions{}); err != nil {
			gone = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !gone || !readable() {
		t.Fatal("deleted Pod's recorded review not readable", gone)
	}
	// A same-name replacement with a new UID never inherits the old review.
	replacement := pod(a.Name)
	if replacement.UID == a.UID || readable() {
		t.Fatal("same-name replacement inherited the recorded review")
	}
}
