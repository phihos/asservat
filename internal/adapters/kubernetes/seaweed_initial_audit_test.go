package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func TestSeaweedInitialAuditCredentialRequiresCurrentPinnedSource(t *testing.T) {
	for _, bad := range []string{"", "pod", "controller", "iam", "subpath", "missing", "foreign-installation", "canceled", "unbounded", "expired"} {
		t.Run(bad, func(t *testing.T) {
			admin, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: swID("2")})
			if err != nil {
				t.Fatal(err)
			}
			original, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: swID("1")})
			if err != nil {
				t.Fatal(err)
			}
			grants := []contracts.SeaweedGrant{{Credential: original, Bucket: "audit", InstallationID: swID("1")}}
			if bad == "missing" {
				grants = nil
			}
			compiled, err := providerconfig.CompileSeaweedStorage(admin, grants)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(compiled.Config)
			target := contracts.SeaweedProviderTarget{
				InstallationID: swID("1"), Namespace: "setup",
				StatefulSet: contracts.WorkerObjectReference{Name: "install-objectstore", UID: swID("3")},
				Pod:         contracts.WorkerObjectReference{Name: "install-objectstore-0", UID: swID("4")},
				Config:      contracts.WorkerObjectReference{Name: "install-objectstore-iam", UID: swID("5")},
				Image:       "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64), ExpectedArgs: providerconfig.SeaweedServerArgs(),
			}
			st := apps.StatefulSet{ObjectMeta: meta.ObjectMeta{Name: target.StatefulSet.Name, UID: types.UID(target.StatefulSet.UID)}}
			pod := core.Pod{
				ObjectMeta: meta.ObjectMeta{Name: target.Pod.Name, UID: types.UID(target.Pod.UID), OwnerReferences: []meta.OwnerReference{{Kind: "StatefulSet", Name: st.Name, UID: st.UID, Controller: ptr.To(true)}}},
				Spec: core.PodSpec{
					Containers: []core.Container{{Name: "seaweed", Image: target.Image, Command: []string{"/usr/bin/weed"}, Args: target.ExpectedArgs, VolumeMounts: []core.VolumeMount{{Name: "iam", MountPath: "/run/asservat/objectstore-iam", ReadOnly: true}}}},
					Volumes:    []core.Volume{{Name: "iam", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: target.Config.Name, Items: []core.KeyToPath{{Key: "s3.json", Path: "s3.json"}}}}}},
				},
				Status: core.PodStatus{Phase: core.PodRunning, ContainerStatuses: []core.ContainerStatus{{Name: "seaweed", Ready: true, ImageID: target.Image, State: core.ContainerState{Running: &core.ContainerStateRunning{StartedAt: meta.Now()}}}}},
			}
			secret := core.Secret{ObjectMeta: meta.ObjectMeta{Name: target.Config.Name, UID: types.UID(target.Config.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"s3.json": compiled.Config}}
			switch bad {
			case "pod":
				pod.UID = types.UID(swID("6"))
			case "controller":
				st.UID = types.UID(swID("6"))
			case "iam":
				secret.UID = types.UID(swID("6"))
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "s3.json"
			case "foreign-installation":
				target.InstallationID = swID("2")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if bad == "unbounded" {
				ctx = context.Background()
			}
			if bad == "expired" {
				expired, end := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer end()
				ctx = expired
			}
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reads++
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					t.Error("credential read attempted mutation")
					http.Error(w, "refused", 403)
					return
				}
				switch {
				case strings.Contains(r.URL.Path, "/statefulsets/"):
					_ = json.NewEncoder(w).Encode(st)
				case strings.Contains(r.URL.Path, "/pods/"):
					_ = json.NewEncoder(w).Encode(pod)
				case strings.Contains(r.URL.Path, "/secrets/"):
					if bad == "canceled" {
						cancel()
					}
					_ = json.NewEncoder(w).Encode(secret)
				default:
					t.Error("unexpected API path")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			provider, err := NewSeaweedProvider(config, target)
			if err != nil {
				t.Fatal(err)
			}
			provider.exec = func(context.Context, []byte) error { t.Error("credential read attempted exec"); return nil }
			got, err := provider.InitialAuditCredential(ctx)
			if bad == "" {
				if err != nil || got != original || reads != 3 {
					t.Fatal("original pinned credential unavailable")
				}
			} else {
				if err == nil || got != (contracts.SeaweedCredential{}) {
					t.Fatal("changed/unbounded source accepted")
				}
				if (bad == "unbounded" || bad == "expired") && reads != 0 {
					t.Fatal("invalid context reached provider")
				}
			}
		})
	}
}
