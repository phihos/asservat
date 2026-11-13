package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type apiProofFixture struct {
	plan               cfg.APIExecutionAdministration
	clock              atomic.Int64
	mu                 sync.Mutex
	object             map[string]any
	creates            int
	podReads           int
	mode               string
	executor, capacity *APIExecutionProtection
	preparer           *APIStartPreparer
	journal            *StartJournal
}

func newAPIProofFixture(t *testing.T, mode string) *apiProofFixture {
	t.Helper()
	f := &apiProofFixture{mode: mode}
	f.clock.Store(time.Now().UTC().Truncate(time.Microsecond).UnixNano())
	now := func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	f.plan = cfg.APIExecutionAdministration{Name: "api-execution", ControlNamespace: cfg.NamespaceRef{Name: "asservat-api", UID: ownerID(1)}, InstallationID: ownerID(2), ClusterID: ownerID(3), IssuerEpoch: ownerID(4), PodName: "executor", PodUID: ownerID(5), Account: "executor", AccountUID: ownerID(6), CapacityAccount: "capacity", CapacityAccountUID: ownerID(7), ProbeAccount: "probe", ProbeAccountUID: ownerID(8), Administrators: []cfg.KubernetesActor{{Kind: "Group", Name: "install-admins"}}}
	pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.PodName, Namespace: f.plan.ControlNamespace.Name, UID: types.UID(f.plan.PodUID), ResourceVersion: "1"}, Spec: core.PodSpec{NodeName: "worker", ServiceAccountName: f.plan.Account, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "executor", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}, Status: core.PodStatus{Phase: core.PodRunning}}
	f.plan.PodSpecDigest = APIExecutionPodDigest(pod.Spec)
	for i := range f.plan.ImageDigest {
		f.plan.ImageDigest[i] = 0xaa
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path
		account := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		uids := map[string]string{"executor": f.plan.AccountUID, "capacity": f.plan.CapacityAccountUID}
		switch {
		case path == "/api/v1/namespaces/asservat-api":
			permissionReply(w, permissionNamespace("asservat-api", f.plan.ControlNamespace.UID))
		case strings.Contains(path, "/serviceaccounts/"):
			name := path[strings.LastIndex(path, "/")+1:]
			uid := uids[name]
			if mode == "replaced-account" && name == "executor" {
				uid = ownerID(90)
			}
			permissionReply(w, core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "asservat-api", UID: types.UID(uid), ResourceVersion: "1"}})
		case path == "/api/v1/namespaces/asservat-api/pods/executor":
			// Plain RBAC replaces the admission guard: only a GET is expected,
			// never a dry-run denial probe.
			if r.Method == "GET" {
				f.podReads++
				out := pod.DeepCopy()
				out.ResourceVersion = fmt.Sprint(f.podReads)
				if mode == "replaced-image" {
					out.Spec.Containers[0].Image = "registry.invalid/other:latest"
				}
				permissionReply(w, out)
				return
			}
			t.Error("unexpected Pod mutation", r.Method)
			http.Error(w, "unexpected", 400)
		case strings.Contains(path, "/capacityreservations"):
			if r.Method == "POST" {
				if account != "capacity" {
					t.Error("wrong create account")
				}
				f.creates++
				if f.object != nil {
					http.Error(w, "exists", 409)
					return
				}
				var o map[string]any
				if json.NewDecoder(r.Body).Decode(&o) != nil {
					t.Error("bad create")
				}
				m := o["metadata"].(map[string]any)
				m["uid"] = ownerID(20)
				m["generation"] = 1
				m["resourceVersion"] = "1"
				f.object = o
				if mode == "lost-create" {
					connection, _, _ := w.(http.Hijacker).Hijack()
					_ = connection.Close()
					return
				}
				if mode == "expired-create" {
					f.clock.Add(int64(5 * time.Second))
				}
			} else if f.object == nil {
				http.NotFound(w, r)
				return
			} else if r.Method == "PUT" {
				var o map[string]any
				_ = json.NewDecoder(r.Body).Decode(&o)
				if o["metadata"].(map[string]any)["resourceVersion"] != f.object["metadata"].(map[string]any)["resourceVersion"] {
					http.Error(w, "conflict", 409)
					return
				}
				if o["status"].(map[string]any)["phase"] == "Ready" && account != "capacity" {
					t.Error("wrong Ready account")
				}
				if o["status"].(map[string]any)["phase"] == "StartCommitted" && account != "executor" {
					t.Error("wrong consume account")
				}
				o["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(time.Now().UnixNano())
				f.object = o
			}
			permissionReply(w, f.object)
		default:
			t.Error("unexpected API request", r.Method, path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := func(account string) (*PermissionClient, *rest.Config) {
		c := &rest.Config{Host: server.URL, BearerToken: account, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
		pc, err := NewPermissionClient(c, f.plan.ClusterID, f.plan.ControlNamespace, now)
		if err != nil {
			t.Fatal(err)
		}
		return pc, c
	}
	executor, executorConfig := client("executor")
	capacity, _ := client("capacity")
	var err error
	f.executor, err = NewAPIExecutionProtection(executor, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	f.capacity, err = NewAPIExecutionProtection(capacity, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	f.preparer, err = NewAPIStartPreparer(f.capacity)
	if err != nil {
		t.Fatal(err)
	}
	f.journal, err = NewStartJournal(executorConfig, f.plan.ClusterID, f.plan.ControlNamespace, now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The executor reads its Pod and account under ordinary RBAC; the fixture
// serves no admission policy, SelfSubjectReview or dry-run endpoint at all.
func TestAPIExecutionProcessUsesLivePinsAndOriginalLifetimeWithoutAdmissionGuard(t *testing.T) {
	for _, mode := range []string{"", "replaced-account", "replaced-image"} {
		t.Run(mode, func(t *testing.T) {
			f := newAPIProofFixture(t, mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, err := NewAPIExecutionProcess(ctx, f.executor)
			if err != nil {
				t.Fatal(err)
			}
			o, err := p.ReadAPIProcess(context.Background())
			if mode != "" {
				if err == nil {
					t.Fatal("invalid role proof accepted")
				}
				return
			}
			if err != nil || !o.Valid(time.Unix(0, f.clock.Load())) {
				t.Fatal(err)
			}
			other, err := NewAPIExecutionProcess(ctx, f.executor)
			if err != nil || other.binding.ProcessEpoch == p.binding.ProcessEpoch {
				t.Fatal("process restart inherited epoch", err)
			}
			cancel()
			if _, err = p.ReadAPIProcess(context.Background()); err == nil {
				t.Fatal("consumer detached original process lifetime")
			}
		})
	}
}
func TestAPIStartPreparationCreatesOnceRecoversExactUIDAndConsumes(t *testing.T) {
	for _, mode := range []string{"", "lost-create", "expired-create"} {
		t.Run(mode, func(t *testing.T) {
			f := newAPIProofFixture(t, mode)
			now := time.Unix(0, f.clock.Load()).UTC()
			b := startRequest(now).Binding
			b.ExecutionClass = artifact.ContextAPIExecution
			b.NodeUID = ""
			b.NodeBootID = ""
			b.ClusterID = f.plan.ClusterID
			b.IssuerEpoch = f.plan.IssuerEpoch
			b.ExecutorPodUID = f.plan.PodUID
			b.ExecutorAccountUID = f.plan.AccountUID
			b.NotAfter = now.Add(5 * time.Second)
			c := value.PreparationCheck{Binding: b, CheckedAt: now, ValidUntil: b.NotAfter, MayCreate: true}
			o, err := f.preparer.PrepareStart(context.Background(), c)
			if mode == "expired-create" {
				if err == nil {
					t.Fatal("expired create acknowledged")
				}
				return
			}
			if mode == "lost-create" {
				if err == nil {
					t.Fatal("lost reply acknowledged")
				}
				c.MayCreate = false
				o, err = f.preparer.PrepareStart(context.Background(), c)
			}
			if err != nil || o.ObjectUID != ownerID(20) || f.creates != 1 {
				t.Fatal(o, err, f.creates)
			}
			r := value.Request{Binding: b, ObjectUID: o.ObjectUID, CheckedAt: now, ValidUntil: c.ValidUntil}
			ready, err := f.preparer.ReadyStart(context.Background(), r)
			if err != nil || ready.Phase != value.Ready || ready.MayStart {
				t.Fatal(ready, err)
			}
			d, err := f.journal.ConsumeStart(context.Background(), r)
			if err != nil || !d.MayStart {
				t.Fatal(d, err)
			}
			d, err = f.journal.LookupStart(context.Background(), r)
			if err != nil || d.MayStart || d.Phase != value.StartCommitted {
				t.Fatal(d, err)
			}
			f.mu.Lock()
			f.object["metadata"].(map[string]any)["uid"] = ownerID(21)
			f.mu.Unlock()
			if _, err = f.preparer.ReadyStart(context.Background(), r); err == nil {
				t.Fatal("replaced start UID accepted")
			}
		})
	}
}
func TestAPIStartMissingAfterUnknownCannotCreate(t *testing.T) {
	f := newAPIProofFixture(t, "")
	now := time.Unix(0, f.clock.Load()).UTC()
	b := startRequest(now).Binding
	b.ExecutionClass = artifact.ContextAPIExecution
	b.NodeUID = ""
	b.NodeBootID = ""
	b.ClusterID = f.plan.ClusterID
	b.IssuerEpoch = f.plan.IssuerEpoch
	b.ExecutorPodUID = f.plan.PodUID
	b.ExecutorAccountUID = f.plan.AccountUID
	b.NotAfter = now.Add(5 * time.Second)
	if _, err := f.preparer.PrepareStart(context.Background(), value.PreparationCheck{Binding: b, CheckedAt: now, ValidUntil: b.NotAfter}); err == nil || f.creates != 0 {
		t.Fatal("unknown state issued a create", err)
	}
}

func TestStartAdmissionScopesIndependentControlNamespaces(t *testing.T) {
	for _, name := range []string{"node-control", "api-control"} {
		p, _, err := StartAdmission(cfg.LocalStartAdministration{Name: "start-" + name, ControlNamespace: cfg.NamespaceRef{Name: name, UID: ownerID(1)}, CapacityUser: "capacity", ExecutionUser: "executor"})
		if err != nil || len(p.Spec.MatchConditions) != 1 || p.Spec.MatchConditions[0].Expression != "request.namespace == "+ownerCELString(name) {
			t.Fatal("global start guard blocks independent namespace", err)
		}
	}
}
