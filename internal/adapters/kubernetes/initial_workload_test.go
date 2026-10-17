package kubernetes

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func initialWorkloadPlan() InitialInstallerWorkloadPlan {
	return InitialInstallerWorkloadPlan{Namespace: "install", Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), Witness: "witness", FleetSource: "fleet", WitnessGuard: "witness-guard", FleetGuard: "fleet-guard", WorkloadGuard: "workload-guard"}
}

func TestInitialWorkloadRejectsInvalidDerivedRBACNames(t *testing.T) {
	p := initialWorkloadPlan()
	p.WriterAccount = strings.Repeat("a", 252)
	if _, err := BuildInitialInstallerWorkload(p); err == nil {
		t.Fatal("accepted a plan whose derived Role name cannot be created")
	}
}

func TestInitialPodBindsEverySecurityRelevantSpecField(t *testing.T) {
	w, err := BuildInitialInstallerWorkload(initialWorkloadPlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Pod.Spec.SchedulingGates) != 1 || w.Pod.Spec.RestartPolicy != core.RestartPolicyNever || *w.Pod.Spec.AutomountServiceAccountToken || *w.Pod.Spec.ActiveDeadlineSeconds != 120 {
		t.Fatal("installer could start or restart implicitly")
	}
	want := InstallationPodSpecDigest(w.Pod.Spec)
	scheduled := w.Pod.Spec.DeepCopy()
	scheduled.NodeName = "node-1"
	scheduled.SchedulingGates = nil
	if InstallationPodSpecDigest(*scheduled) != want {
		t.Fatal("normal scheduling changed identity")
	}
	for _, change := range []func(*core.PodSpec){
		func(s *core.PodSpec) { s.Containers[0].Image = "other:latest" },
		func(s *core.PodSpec) { s.Containers[0].Command = []string{"/bin/sh"} },
		func(s *core.PodSpec) { s.ServiceAccountName = "administrator" },
		func(s *core.PodSpec) { s.Volumes[0].Projected.Sources[1].Secret.Name = "other-credentials" },
		func(s *core.PodSpec) { s.HostPID = true },
		func(s *core.PodSpec) {
			s.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "debug", Image: "other:latest"}}}
		},
	} {
		s := w.Pod.Spec.DeepCopy()
		change(s)
		if InstallationPodSpecDigest(*s) == want {
			t.Fatal("security mutation escaped spec binding")
		}
	}
	for _, r := range w.Roles {
		for _, rule := range r.Rules {
			for _, res := range rule.Resources {
				if res == "secrets" || res == "*" || res == "serviceaccounts/token" || res == "pods/exec" {
					t.Fatal("installer can read/mint/inject credentials", r.Name, res)
				}
			}
		}
	}
}

func TestInitialWriterRequiresLiveAccountDespiteCachedAuthentication(t *testing.T) {
	for _, mode := range []string{"valid", "unbound", "other-pod", "replaced-account", "deleted-account", "administrator"} {
		t.Run(mode, func(t *testing.T) {
			p := cfg.InitialWorkloadAdministration{ControlNamespace: cfg.NamespaceRef{Name: "install", UID: ownerID(1)}, PodName: "installer", PodUID: ownerID(2), WriterAccount: "writer", WriterAccountUID: ownerID(3), Administrators: []cfg.KubernetesActor{{Kind: "Group", Name: "install-admins"}}}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					who := auth.SelfSubjectReview{}
					who.Status.UserInfo = auth.UserInfo{Username: "system:serviceaccount:install:writer", UID: p.WriterAccountUID, Groups: []string{"system:authenticated"}, Extra: map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-name": {p.PodName}, "authentication.kubernetes.io/pod-uid": {p.PodUID}}}
					if mode == "unbound" {
						who.Status.UserInfo.Extra = nil
					}
					if mode == "other-pod" {
						who.Status.UserInfo.Extra["authentication.kubernetes.io/pod-uid"] = auth.ExtraValue{ownerID(4)}
					}
					if mode == "administrator" {
						who.Status.UserInfo.Groups = append(who.Status.UserInfo.Groups, "install-admins")
					}
					permissionReply(w, who)
				case "/api/v1/namespaces/install/serviceaccounts/writer":
					if mode == "deleted-account" {
						http.NotFound(w, r)
						return
					}
					sa := core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: p.WriterAccount, Namespace: "install", UID: types.UID(p.WriterAccountUID), ResourceVersion: "1"}}
					if mode == "replaced-account" {
						sa.UID = types.UID(ownerID(8))
					}
					permissionReply(w, sa)
				default:
					t.Error("unexpected API request", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, ownerID(9), p.ControlNamespace, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			g := &InitialWorkloadProtection{guard: &configMapProtection{observer: client}, plan: p}
			err = g.account(context.Background(), client, p.WriterAccount, p.WriterAccountUID, true)
			if (mode == "valid") != (err == nil) {
				t.Fatal(mode, err)
			}
		})
	}
}
