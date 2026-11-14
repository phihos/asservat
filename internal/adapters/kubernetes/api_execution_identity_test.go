package kubernetes

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type apiProofFixture struct {
	plan     cfg.APIExecutionAdministration
	clock    atomic.Int64
	mu       sync.Mutex
	podReads int
	executor *APIExecutionProtection
}

func newAPIProofFixture(t *testing.T, mode string) *apiProofFixture {
	t.Helper()
	f := &apiProofFixture{}
	f.clock.Store(time.Now().UTC().Truncate(time.Microsecond).UnixNano())
	now := func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	f.plan = cfg.APIExecutionAdministration{Name: "api-execution", ControlNamespace: cfg.NamespaceRef{Name: "asservat-api", UID: ownerID(1)}, InstallationID: ownerID(2), ClusterID: ownerID(3), IssuerEpoch: ownerID(4), PodName: "executor", PodUID: ownerID(5), Account: "executor", AccountUID: ownerID(6), ProbeAccount: "probe", ProbeAccountUID: ownerID(8), Administrators: []cfg.KubernetesActor{{Kind: "Group", Name: "install-admins"}}}
	pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.PodName, Namespace: f.plan.ControlNamespace.Name, UID: types.UID(f.plan.PodUID), ResourceVersion: "1"}, Spec: core.PodSpec{NodeName: "worker", ServiceAccountName: f.plan.Account, SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Containers: []core.Container{{Name: "executor", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}, Status: core.PodStatus{Phase: core.PodRunning}}
	f.plan.PodSpecDigest = APIExecutionPodDigest(pod.Spec)
	for i := range f.plan.ImageDigest {
		f.plan.ImageDigest[i] = 0xaa
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path
		uids := map[string]string{"executor": f.plan.AccountUID}
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
		default:
			t.Error("unexpected API request", r.Method, path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := func(account string) *PermissionClient {
		c := &rest.Config{Host: server.URL, BearerToken: account, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
		pc, err := NewPermissionClient(c, f.plan.ClusterID, f.plan.ControlNamespace, now)
		if err != nil {
			t.Fatal(err)
		}
		return pc
	}
	var err error
	f.executor, err = NewAPIExecutionProtection(client("executor"), f.plan)
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
