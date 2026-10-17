package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func TestLocalStartWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_PERMISSION_FIXTURE")
	if path == "" {
		t.Skip("run make permission-integration")
	}
	var fixture struct{ Config string }
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &fixture) != nil {
		t.Fatal("fixture unavailable")
	}
	c, err := clientcmd.BuildConfigFromFlags("", fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	core, err := kubernetes.NewForConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ns, err := core.CoreV1().Namespaces().Get(ctx, "asservat-system", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	control := configuration.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
	// Deliberately broad fixture CRUD: admission must separate producer/consumer
	// even if a Role was accidentally broadened. Runtime roles will be narrower.
	_, err = core.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "start-test"}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations", "capacityreservations/status"}, Verbs: []string{"get", "create", "update", "patch", "delete"}}, {APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "start-test"}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "fixture-start"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "start-test"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "start-test"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "start-test"}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "fixture-start"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: "start-test"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	actor := func(user string) (dynamic.ResourceInterface, *rest.Config) {
		cp := rest.CopyConfig(c)
		cp.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: []string{"fixture-start"}}
		d, e := dynamic.NewForConfig(cp)
		if e != nil {
			t.Fatal(e)
		}
		return d.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(ns.Name), cp
	}
	capacity, _ := actor("fixture-capacity")
	execution, executionConfig := actor("fixture-execution")
	outsider, _ := actor("fixture-start-outsider")
	p, binding, err := kube.StartAdmission(configuration.LocalStartAdministration{Name: "asservat-start-test", ControlNamespace: control, CapacityUser: "fixture-capacity", ExecutionUser: "fixture-execution"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	const cluster = "11111111-1111-4111-8111-111111111111"
	newObject := func() (*unstructured.Unstructured, value.Binding) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		v := value.Binding{OperationID: uuid.NewString(), CaptureID: uuid.NewString(), AttemptID: uuid.NewString(), ClusterID: cluster, IssuerEpoch: uuid.NewString(), PodUID: uuid.NewString(), NodeUID: uuid.NewString(), NodeBootID: uuid.NewString(), CollectorEpoch: uuid.NewString(), ActionID: "pod-status", ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: 4096, NotBefore: now, NotAfter: now.Add(time.Minute)}
		s, e := kube.LocalStartSpec(v)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(s)
		var sm map[string]any
		_ = json.Unmarshal(raw, &sm)
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CapacityReservation", "metadata": map[string]any{"name": "start-" + v.AttemptID, "namespace": ns.Name}, "spec": sm}}, v
	}
	dry := meta.CreateOptions{DryRun: []string{meta.DryRunAll}, FieldValidation: "Strict"}
	for i := 0; i < 100; i++ {
		o, _ := newObject()
		_, err = outsider.Create(ctx, o, dry)
		if (apierrors.IsInvalid(err) || apierrors.IsForbidden(err)) && strings.Contains(err.Error(), "Capacity prepares") {
			break
		}
		if i == 99 {
			t.Fatalf("guard failed to enforce: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	current, err := core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, p.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if current.Status.TypeChecking != nil && len(current.Status.TypeChecking.ExpressionWarnings) > 0 {
		t.Fatalf("CEL warnings: %+v", current.Status.TypeChecking.ExpressionWarnings)
	}
	o, v := newObject()
	if _, err = execution.Create(ctx, o, dry); err == nil {
		t.Fatal("execution minted reservation")
	}
	o, err = capacity.Create(ctx, o, meta.CreateOptions{FieldValidation: "Strict"})
	if err != nil {
		t.Fatal(err)
	}
	r := value.Request{Binding: v, ObjectUID: string(o.GetUID())}
	refresh := func() { r.CheckedAt = time.Now().UTC(); r.ValidUntil = r.CheckedAt.Add(5 * time.Second) }
	refresh()
	journal, err := kube.NewStartJournal(executionConfig, cluster, control, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("requires-prepaid-ready", func(t *testing.T) {
		if d, e := journal.ConsumeStart(ctx, r); e == nil || d.MayStart {
			t.Fatal("unready reservation allowed", d, e)
		}
		_ = unstructured.SetNestedMap(o.Object, map[string]any{"phase": "Ready"}, "status")
		if _, e := execution.UpdateStatus(ctx, o, meta.UpdateOptions{}); e == nil {
			t.Fatal("execution marked Ready")
		}
		var e error
		o, e = capacity.UpdateStatus(ctx, o, meta.UpdateOptions{FieldValidation: "Strict"})
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("one-real-cas-and-restart", func(t *testing.T) {
		refresh()
		var wg sync.WaitGroup
		var starts atomic.Int64
		for range 8 {
			wg.Go(func() {
				d, e := journal.ConsumeStart(ctx, r)
				if e != nil && !errors.Is(e, value.ErrConflict) && !errors.Is(e, value.ErrDenied) {
					t.Error(e)
				}
				if d.MayStart {
					starts.Add(1)
				}
			})
		}
		wg.Wait()
		if starts.Load() != 1 {
			t.Fatal("starts", starts.Load())
		}
		restarted, e := kube.NewStartJournal(executionConfig, cluster, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		d, e := restarted.ConsumeStart(ctx, r)
		if e != nil || d.MayStart || d.Phase != value.StartCommitted {
			t.Fatal(d, e)
		}
	})
	t.Run("no-reset-mutation-or-delete", func(t *testing.T) {
		cur, e := capacity.Get(ctx, o.GetName(), meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		reset := cur.DeepCopy()
		_ = unstructured.SetNestedMap(reset.Object, map[string]any{"phase": "Ready"}, "status")
		for _, role := range []dynamic.ResourceInterface{capacity, execution, outsider} {
			if _, e = role.UpdateStatus(ctx, reset, meta.UpdateOptions{}); e == nil {
				t.Fatal("reset accepted")
			}
			if _, e = role.Patch(ctx, cur.GetName(), types.MergePatchType, []byte(`{"spec":{"nativeBytes":8192}}`), meta.PatchOptions{}); e == nil {
				t.Fatal("scope widening accepted")
			}
			if e = role.Delete(ctx, cur.GetName(), meta.DeleteOptions{}); e == nil {
				t.Fatal("spend deletion accepted")
			}
		}
		changed := r
		changed.Binding.CollectorEpoch = uuid.NewString()
		if d, e := journal.ConsumeStart(ctx, changed); e == nil || d.MayStart {
			t.Fatal("collector replacement adopted old record")
		}
	})
	t.Run("schema-bounds-and-owner-gc", func(t *testing.T) {
		for _, kind := range []string{"deadline", "owner", "unknown", "wrong-name", "zero-bytes"} {
			x, _ := newObject()
			switch kind {
			case "deadline":
				_ = unstructured.SetNestedField(x.Object, time.Now().Add(2*time.Minute).UTC().Format(time.RFC3339Nano), "spec", "notAfter")
			case "owner":
				x.SetOwnerReferences([]meta.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "parent", UID: types.UID(uuid.NewString())}})
			case "unknown":
				_ = unstructured.SetNestedField(x.Object, "unreviewed", "spec", "command")
			case "wrong-name":
				x.SetName("start-" + uuid.NewString())
			case "zero-bytes":
				_ = unstructured.SetNestedField(x.Object, int64(0), "spec", "nativeBytes")
			}
			if _, e := capacity.Create(ctx, x, dry); e == nil {
				t.Fatal("invalid reservation accepted", kind)
			}
		}
	})

	t.Run("api-start-requires-matching-pod-bound-identity", func(t *testing.T) {
		// This tests real CRD/CEL enforcement with explicit synthetic impersonation;
		// it does not qualify an in-Pod executor or replace native process proof.
		_, b := newObject()
		b.ExecutionClass = artifact.ContextAPIExecution
		b.NodeUID = ""
		b.NodeBootID = ""
		b.ExecutorPodUID = uuid.NewString()
		b.ExecutorAccountUID = uuid.NewString()
		b.NotAfter = b.NotBefore.Add(5 * time.Second)
		spec, e := kube.LocalStartSpec(b)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := json.Marshal(spec)
		var m map[string]any
		_ = json.Unmarshal(data, &m)
		o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CapacityReservation", "metadata": map[string]any{"name": "start-" + b.AttemptID, "namespace": ns.Name}, "spec": m}}
		wide := o.DeepCopy()
		_ = unstructured.SetNestedField(wide.Object, b.NotBefore.Add(6*time.Second).Format(time.RFC3339Nano), "spec", "notAfter")
		if _, e = capacity.Create(ctx, wide, meta.CreateOptions{DryRun: []string{meta.DryRunAll}}); !apierrors.IsInvalid(e) {
			t.Fatalf("API profile accepted an extended original interval: %v", e)
		}
		o, e = capacity.Create(ctx, o, meta.CreateOptions{FieldValidation: "Strict"})
		if e != nil {
			t.Fatal(e)
		}
		_ = unstructured.SetNestedMap(o.Object, map[string]any{"phase": "Ready"}, "status")
		o, e = capacity.UpdateStatus(ctx, o, meta.UpdateOptions{FieldValidation: "Strict"})
		if e != nil {
			t.Fatal(e)
		}
		committed := o.DeepCopy()
		_ = unstructured.SetNestedMap(committed.Object, map[string]any{"phase": "StartCommitted", "committedAt": time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)}, "status")
		if _, e = execution.UpdateStatus(ctx, committed, meta.UpdateOptions{DryRun: []string{meta.DryRunAll}}); e == nil {
			t.Fatal("unbound identity consumed API start")
		}
		bound := rest.CopyConfig(executionConfig)
		bound.Impersonate.UID = b.ExecutorAccountUID
		bound.Impersonate.Extra = map[string][]string{"authentication.kubernetes.io/pod-uid": {b.ExecutorPodUID}}
		product, e := kube.NewStartJournal(bound, cluster, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		checked := time.Now().UTC()
		result, e := product.ConsumeStart(ctx, value.Request{Binding: b, ObjectUID: string(o.GetUID()), CheckedAt: checked, ValidUntil: b.NotAfter})
		if e != nil || !result.MayStart {
			t.Fatal("exact Pod-bound API start rejected", result, e)
		}
	})

	t.Run("independent-start-namespaces-coexist-without-foreign-authority", func(t *testing.T) {
		otherNS, e := core.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: meta.ObjectMeta{Name: "api-start-other", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		otherControl := configuration.NamespaceRef{Name: otherNS.Name, UID: string(otherNS.UID)}
		role := &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "start-other", Namespace: otherNS.Name}, Rules: []rbac.PolicyRule{{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations", "capacityreservations/status"}, Verbs: []string{"get", "create", "update"}}}}
		if _, e = core.RbacV1().Roles(otherNS.Name).Create(ctx, role, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		rb := &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name, Namespace: otherNS.Name}, Subjects: []rbac.Subject{{Kind: "Group", APIGroup: rbac.GroupName, Name: "fixture-start"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role.Name}}
		if _, e = core.RbacV1().RoleBindings(otherNS.Name).Create(ctx, rb, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		cr, e := core.RbacV1().ClusterRoles().Get(ctx, "start-test", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		cr.Rules[0].ResourceNames = append(cr.Rules[0].ResourceNames, otherNS.Name)
		if _, e = core.RbacV1().ClusterRoles().Update(ctx, cr, meta.UpdateOptions{}); e != nil {
			t.Fatal(e)
		}
		otherPolicy, otherBinding, e := kube.StartAdmission(configuration.LocalStartAdministration{Name: "asservat-start-other", ControlNamespace: otherControl, CapacityUser: "fixture-capacity", ExecutionUser: "fixture-execution"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = core.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, otherPolicy, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = core.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, otherBinding, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		_, capacityConfig := actor("fixture-capacity")
		dc, e := dynamic.NewForConfig(capacityConfig)
		if e != nil {
			t.Fatal(e)
		}
		otherCapacity := dc.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(otherNS.Name)
		_, outsiderConfig := actor("fixture-start-outsider")
		outsideClient, e := dynamic.NewForConfig(outsiderConfig)
		if e != nil {
			t.Fatal(e)
		}
		otherOutsider := outsideClient.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(otherNS.Name)
		for attempt := 0; attempt < 100; attempt++ {
			probe, _ := newObject()
			probe.SetNamespace(otherNS.Name)
			_, probeErr := otherOutsider.Create(ctx, probe, dry)
			if (apierrors.IsForbidden(probeErr) || apierrors.IsInvalid(probeErr)) && strings.Contains(probeErr.Error(), "asservat-start-other") && strings.Contains(probeErr.Error(), "Capacity prepares") {
				break
			}
			if attempt == 99 {
				t.Fatal("second independent guard not enforced", probeErr)
			}
			time.Sleep(50 * time.Millisecond)
		}
		x, b := newObject()
		x.SetNamespace(otherNS.Name)
		// Both policies stay installed. The old global match denies this create even
		// to the correct second capacity account: the first guard sees a foreign NS.
		x, e = otherCapacity.Create(ctx, x, meta.CreateOptions{FieldValidation: "Strict"})
		if e != nil {
			t.Fatal("independent namespace blocked by another start guard", e)
		}
		_ = unstructured.SetNestedMap(x.Object, map[string]any{"phase": "Ready"}, "status")
		x, e = otherCapacity.UpdateStatus(ctx, x, meta.UpdateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		checked := time.Now().UTC()
		request := value.Request{Binding: b, ObjectUID: string(x.GetUID()), CheckedAt: checked, ValidUntil: checked.Add(5 * time.Second)}
		if result, e := journal.ConsumeStart(ctx, request); e == nil || result.MayStart {
			t.Fatal("foreign namespace authorized original journal", result, e)
		}
		otherJournal, e := kube.NewStartJournal(executionConfig, cluster, otherControl, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		result, e := otherJournal.ConsumeStart(ctx, request)
		if e != nil || !result.MayStart {
			t.Fatal("separate exact namespace failed", result, e)
		}
	})
	t.Run("pinned-work-trust-read-only-role", func(t *testing.T) {
		data, e := os.ReadFile("../../examples/work-trust.json")
		if e != nil {
			t.Fatal(e)
		}
		cm, e := core.CoreV1().ConfigMaps(ns.Name).Create(ctx, &corev1.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "work-trust"}, Data: map[string]string{"work-trust.json": string(data)}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_, e = core.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "work-trust-read"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{cm.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_, e = core.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "work-trust-read"}, Subjects: []rbac.Subject{{Kind: "User", APIGroup: rbac.GroupName, Name: "fixture-execution"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "work-trust-read"}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		client, e := kube.NewPermissionClient(executionConfig, cluster, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		reader, e := kube.NewWorkTrustClient(client, cm.Name, string(cm.UID))
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now()
		receiver := fleetvalue.Receiver{CollectorEpoch: uuid.NewString(), PeerID: uuid.NewString(), ClusterID: cluster, IssuerEpoch: "22222222-2222-4222-8222-222222222222", NodeUID: uuid.NewString(), NodeBootID: uuid.NewString(), Region: "fixture", Capabilities: []string{"pod-status/v1"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
		trust, e := reader.WorkTrust(ctx, receiver)
		if e != nil || len(trust.Keys) != 1 || trust.Revision.UID != string(cm.UID) {
			t.Fatal(trust, e)
		}
		readCore, e := kubernetes.NewForConfig(executionConfig)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = readCore.CoreV1().ConfigMaps(ns.Name).Update(ctx, cm, meta.UpdateOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("trust reader could mutate trust", e)
		}
		if e = core.CoreV1().ConfigMaps(ns.Name).Delete(ctx, cm.Name, meta.DeleteOptions{}); e != nil {
			t.Fatal(e)
		}
		cm.ResourceVersion = ""
		cm.UID = ""
		if _, e = core.CoreV1().ConfigMaps(ns.Name).Create(ctx, cm, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = reader.WorkTrust(ctx, receiver); e == nil {
			t.Fatal("replacement trust silently adopted")
		}
	})
	t.Run("pinned-fleet-administration-read-only-role", func(t *testing.T) {
		data, e := os.ReadFile("../../examples/fleet-settings.json")
		if e != nil {
			t.Fatal(e)
		}
		cm, e := core.CoreV1().ConfigMaps(ns.Name).Create(ctx, &corev1.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "fleet-settings"}, Data: map[string]string{"fleet.json": string(data)}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_, e = core.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: "fleet-settings-read"}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{cm.Name}, Verbs: []string{"get"}}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_, e = core.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "fleet-settings-read"}, Subjects: []rbac.Subject{{Kind: "User", APIGroup: rbac.GroupName, Name: "fixture-execution"}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: "fleet-settings-read"}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		client, e := kube.NewPermissionClient(executionConfig, cluster, control, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		reader, e := kube.NewFleetSettingsClient(client, cm.Name, string(cm.UID), cluster)
		if e != nil {
			t.Fatal(e)
		}
		settings, e := reader.FleetAdministration(ctx)
		if e != nil || settings.InstallationID != cluster || settings.Revision.UID != string(cm.UID) || len(settings.Groups) != 1 {
			t.Fatal(settings, e)
		}
		readCore, e := kubernetes.NewForConfig(executionConfig)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = readCore.CoreV1().ConfigMaps(ns.Name).Update(ctx, cm, meta.UpdateOptions{}); !apierrors.IsForbidden(e) {
			t.Fatal("trust reader could mutate trust", e)
		}
		if e = core.CoreV1().ConfigMaps(ns.Name).Delete(ctx, cm.Name, meta.DeleteOptions{}); e != nil {
			t.Fatal(e)
		}
		cm.ResourceVersion = ""
		cm.UID = ""
		if _, e = core.CoreV1().ConfigMaps(ns.Name).Create(ctx, cm, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = reader.FleetAdministration(ctx); e == nil {
			t.Fatal("replacement trust silently adopted")
		}
	})
	t.Run("journal-pins-control-namespace-uid", func(t *testing.T) {
		wrong := control
		wrong.UID = uuid.NewString()
		denied, e := kube.NewStartJournal(executionConfig, cluster, wrong, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		refresh()
		if d, e := denied.ConsumeStart(ctx, r); !errors.Is(e, value.ErrConflict) || d.MayStart {
			t.Fatal("recreated namespace authorized a start", d, e)
		}
		if d, e := denied.LookupStart(ctx, r); !errors.Is(e, value.ErrConflict) || d.MayStart {
			t.Fatal("recreated namespace adopted spend", d, e)
		}
	})
}
