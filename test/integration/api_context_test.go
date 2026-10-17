package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// Reuse the real SQL/S3/OpenBao fixture and production encrypted artifact path.
// Target resolution and acquisition use a separate actual service account with
// no Node, exec, logs, Secret or write permission. Accepted human/capability,
// audience and retention values here remain explicitly synthetic test facts;
// the separate admission fixture qualifies SQL acceptance of this exact class.
func qualifyAPIContextAcquisition(t *testing.T, ctx context.Context, f fixture, adminSQL *pgxpool.Pool, ledger *postgres.Ledger, sealer evidence.KeySealer, keys evidence.KeyOpener, store *objectstore.Store) {
	t.Helper()
	cluster := f.Clusters[0]
	config, err := clientcmd.BuildConfigFromFlags("", cluster.Config)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ns, name := cluster.Pod.Namespace, "api-context-reader"
	cleanup := func(remove func(context.Context) error) {
		t.Cleanup(func() {
			c, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := remove(c); err != nil && !apierrors.IsNotFound(err) {
				t.Error("API context fixture cleanup:", err)
			}
		})
	}
	sa, err := admin.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		return admin.CoreV1().ServiceAccounts(ns).Delete(c, name, exactTargetDelete(sa.UID))
	})
	role, err := admin.RbacV1().Roles(ns).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets", "statefulsets"}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		return admin.RbacV1().Roles(ns).Delete(c, name, exactTargetDelete(role.UID))
	})
	binding, err := admin.RbacV1().RoleBindings(ns).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns}}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: name}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		return admin.RbacV1().RoleBindings(ns).Delete(c, name, exactTargetDelete(binding.UID))
	})
	nsRole, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		return admin.RbacV1().ClusterRoles().Delete(c, name, exactTargetDelete(nsRole.UID))
	})
	nsBinding, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns}}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: name}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		return admin.RbacV1().ClusterRoleBindings().Delete(c, name, exactTargetDelete(nsBinding.UID))
	})
	token, err := admin.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("fixture service account token unavailable")
	}
	readerConfig := rest.AnonymousClientConfig(config)
	readerConfig.BearerToken = token.Status.Token
	reader, err := kubernetes.NewForConfig(readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	original, err := admin.AppsV1().Deployments(ns).Get(ctx, "fixture", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	spec := original.Spec.DeepCopy()
	spec.Replicas = ptr.To(int32(1))
	spec.Selector = &meta.LabelSelector{MatchLabels: map[string]string{"app": "api-context-unscheduled"}}
	spec.Template.Labels = spec.Selector.MatchLabels
	spec.Template.Spec.SchedulerName = "asservat-test-no-scheduler"
	deployment, err := admin.AppsV1().Deployments(ns).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "api-context-unscheduled", Namespace: ns}, Spec: *spec}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func(c context.Context) error {
		if err := admin.AppsV1().Deployments(ns).Delete(c, deployment.Name, exactTargetDelete(deployment.UID)); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return wait.PollUntilContextCancel(c, 100*time.Millisecond, true, func(c context.Context) (bool, error) {
			_, err := admin.AppsV1().Deployments(ns).Get(c, deployment.Name, meta.GetOptions{})
			return apierrors.IsNotFound(err), nonNotFound(err)
		})
	})
	var pod core.Pod
	if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 20*time.Second, true, func(c context.Context) (bool, error) {
		pods, err := reader.CoreV1().Pods(ns).List(c, meta.ListOptions{LabelSelector: "app=api-context-unscheduled"})
		if apierrors.IsForbidden(err) {
			return false, nil // Only wait for newly created fixture RBAC.
		}
		if err != nil {
			return false, err
		}
		if len(pods.Items) != 1 {
			return false, nil
		}
		pod = pods.Items[0]
		return true, nil
	}); err != nil || pod.Spec.NodeName != "" {
		t.Fatal("actual unscheduled Pod unavailable", err)
	}
	if _, err := reader.CoreV1().Nodes().Get(ctx, cluster.Pod.NodeName, meta.GetOptions{}); !apierrors.IsForbidden(err) {
		t.Fatal("API reader unexpectedly has Node permission", err)
	}
	if err := reader.CoreV1().RESTClient().Post().Namespace(ns).Resource("pods").Name(pod.Name).SubResource("exec").Param("command", "true").Do(ctx).Error(); !apierrors.IsForbidden(err) {
		t.Fatal("API reader unexpectedly has Pod exec permission", err)
	}
	clusterID := custodyID()
	observations, err := kube.NewPermissionClient(readerConfig, clusterID, cfg.NamespaceRef{Name: ns, UID: cluster.Pod.NamespaceUID}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := kube.NewAPIContextTargets(observations)
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolver.ResolveWorkload(ctx, targets.WorkloadRequest{ClusterID: clusterID, Namespace: ns, Kind: "Deployment", Name: deployment.Name})
	if err != nil || target.ExecutionClass != artifact.ContextAPIExecution || target.Request.PodUID != string(pod.UID) || target.Request.Workload.UID != string(deployment.UID) || target.Pin.NodeName != "" || target.NodeUID != "" || target.NodeBootID != "" {
		t.Fatal("API resolution lost Pod/owner identity or invented node authority", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	policies := privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "synthetic-policies", Generation: 1, Digest: artifact.Digest{1}}, Complete: true, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Policies: []privacy.Policy{{Revision: identity.Revision{UID: "synthetic-retention", Generation: 1, Digest: artifact.Digest{2}}, Baseline: true, PurposeRef: "synthetic-diagnostics", DefaultSeconds: 120, MaximumSeconds: 300, DeletionBudgetSeconds: 30}}}
	retention, err := privacy.Resolve(policies, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planning.CompileContext(planvalue.ContextInput{CaptureID: custodyID(), Executor: identity.Principal{Issuer: "https://identity.example.invalid", Subject: "synthetic-developer", ClientID: "synthetic", Kind: identity.Human}, Deadline: now.Add(time.Minute), Target: target, Retention: retention, Capability: planvalue.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Revision: identity.Revision{UID: "synthetic-api-capability", Generation: 1, Digest: artifact.Digest{3}}, Enabled: true, CollectorVersion: "synthetic-in-process", CollectorImageDigest: artifact.Digest{4}, ProjectionDigest: planning.ProjectionDigest(), ObservedAt: now, FreshUntil: now.Add(30 * time.Second)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, Registration: artifact.Registration{Location: artifact.Location{ClusterID: clusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: custodyID(), AllocationID: custodyID(), PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: plan.Input.Deadline, ExpiresAt: retention.ExpiresAt, DeleteBy: retention.DeleteBy}, CaseID: custodyID(), OccurrenceID: custodyID(), PodUID: target.Pin.UID, Namespace: ns, NamespaceUID: target.Pin.NamespaceUID, WorkloadUID: target.Request.Workload.UID, CollectorVersion: plan.Input.Capability.CollectorVersion, CollectorImageDigest: plan.Input.Capability.CollectorImageDigest, RecipeDigest: plan.RecipeDigest, PlanDigest: plan.ScopeDigest, CaptureUID: plan.Input.CaptureID, ActionID: "pod-status", DataClass: "metadata", PurposeRef: retention.PurposeRef, Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "synthetic-binding", AssignmentID: custodyID(), BasisDigest: artifact.Digest{5}}}, RequestedAgeSeconds: retention.RequestedSeconds, MaximumAgeSeconds: retention.MaximumSeconds, DeletionBudgetSeconds: retention.DeletionBudgetSeconds, RetentionRules: retention.Policies, TriggeredAt: now}
	poolID := custodyID()
	if _, err := adminSQL.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,4)", poolID, e.Registration.StoreID, now.Add(time.Hour), e.Registration.ReservedBytes()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: e.Registration.AllocationID, PoolID: poolID, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: e.Registration.ReservedBytes(), Objects: 4, ValidUntil: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Register(ctx, e.Registration); err != nil {
		t.Fatal(err)
	}
	bound, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewContextProducer(bound, sealer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.PrepareContext(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	collector, err := kube.NewAPIContextClient(readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	native, err := collector.Capture(ctx, target.Pin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(native)
	var projection struct{ Phase, PodUID string }
	if json.Unmarshal(native, &projection) != nil || projection.Phase != "Pending" || projection.PodUID != string(pod.UID) {
		t.Fatal("native projection did not capture actual unscheduled Pod")
	}
	copies, err := prepared.StoreContext(ctx, native, started, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := objectstore.NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := (evidence.ContextCustodian{Ledger: ledger, Verifier: verifier}).VerifyAndStore(ctx, e, copies); err != nil {
		t.Fatal(err)
	}
	record, err := ledger.Lookup(ctx, e.Registration.Location)
	if err != nil || record.State != artifact.StoredUnpublished {
		t.Fatal("API artifact not verified into unpublished custody", err)
	}
	nativeReader, err := objectstore.NewContextNativeReader(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	read, err := nativeReader.ReadContext(ctx, e, copies, time.Now().Add(5*time.Second))
	defer clear(read)
	if err != nil || !bytes.Equal(read, native) {
		t.Fatal("API context native bytes did not survive encrypted verification", err)
	}
	wrong := e
	wrong.ExecutionClass = artifact.ContextNodeExecution
	wrong.NodeUID, wrong.NodeBootID = cluster.NodeUID, cluster.NodeBootID
	if err := verifier.VerifyContext(ctx, wrong, copies); err == nil {
		t.Fatal("API artifact promoted to node execution identity")
	}
	t.Logf("actual unscheduled Pod resolved and captured with Node/exec denied; %d native bytes; encrypted full verification and exact native read; stored_unpublished, synthetic authority remains fixture-only", len(native))
}
