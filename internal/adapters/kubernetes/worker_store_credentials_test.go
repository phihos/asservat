package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestNativeWorkerSecretIdentityAndImmutableProjection(t *testing.T) {
	const uid = "11111111-1111-4111-8111-111111111119"
	for _, mode := range []string{"valid", "replaced", "mutable", "deleting", "extra-file", "oversized", "missing-file", "wrong-kind", "forbidden"} {
		t.Run(mode, func(t *testing.T) {
			yes := true
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "native-reader", Namespace: permissionControl.Name, UID: types.UID(uid), ResourceVersion: "one"}, Type: core.SecretTypeOpaque, Immutable: &yes, Data: map[string][]byte{"credentials.json": []byte(`{"accessKeyID":"synthetic","secretAccessKey":"synthetic"}`)}}
			switch mode {
			case "replaced":
				secret.UID = types.UID(permissionCluster)
			case "mutable":
				secret.Immutable = nil
			case "deleting":
				now := meta.Now()
				secret.DeletionTimestamp = &now
			case "extra-file":
				secret.Data["extra"] = []byte("synthetic")
			case "oversized":
				secret.Data["credentials.json"] = make([]byte, 16<<10+1)
			case "missing-file":
				delete(secret.Data, "credentials.json")
			case "wrong-kind":
				secret.Kind = "ConfigMap"
			}
			reads := 0
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/"+permissionControl.Name+"/secrets/native-reader" {
					return false
				}
				reads++
				if mode == "forbidden" {
					w.WriteHeader(http.StatusForbidden)
				} else {
					permissionReply(w, secret)
				}
				return true
			})
			p := value.DownloadWorkerProfile{Namespace: permissionControl.Name, StoreCredentialSecret: "native-reader", StoreCredentialSecretUID: uid}
			err := checkWorkerStoreSecret(context.Background(), f.client, p)
			if (err == nil) != (mode == "valid") || reads != 1 {
				t.Fatalf("native credential observation mode=%s reads=%d err=%v", mode, reads, err)
			}
		})
	}
}

func TestNativeWorkerJobPinsOnlyTheScopedCredentialFile(t *testing.T) {
	p := value.DownloadWorkerProfile{Namespace: "workers", ServiceAccount: "acquisition", Image: "example.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", CPUMillis: 100, MemoryBytes: 64 << 20, StoreCredentialSecret: "native-reader", StoreCredentialSecretUID: "11111111-1111-4111-8111-111111111119"}
	i := value.DownloadWorkerIntent{ID: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222", Profile: p, CreatedAt: time.Now().UTC(), RunUntil: time.Now().UTC().Add(time.Minute)}
	for _, mode := range []string{"valid", "replacement-secret", "all-secret-keys", "writable", "wrong-mount", "optional", "unrestricted-mode"} {
		t.Run(mode, func(t *testing.T) {
			job := workerJob(i)
			job.UID = "job-uid"
			job.ResourceVersion = "one"
			pod := &job.Spec.Template.Spec
			if len(pod.Volumes) != 3 || len(pod.Containers[0].VolumeMounts) != 3 || *pod.AutomountServiceAccountToken || !*pod.SecurityContext.RunAsNonRoot {
				t.Fatal("native projection changed restricted worker shape")
			}
			secret := pod.Volumes[2].Secret
			if secret == nil || secret.SecretName != p.StoreCredentialSecret || len(secret.Items) != 1 || secret.Items[0].Key != "credentials.json" || !pod.Containers[0].VolumeMounts[2].ReadOnly {
				t.Fatal("missing scoped native projection")
			}
			switch mode {
			case "replacement-secret":
				secret.SecretName = "other"
			case "all-secret-keys":
				secret.Items = nil
			case "writable":
				pod.Containers[0].VolumeMounts[2].ReadOnly = false
			case "wrong-mount":
				pod.Containers[0].VolumeMounts[2].MountPath = "/tmp"
			case "optional":
				yes := true
				secret.Optional = &yes
			case "unrestricted-mode":
				mode := int32(0666)
				secret.DefaultMode = &mode
			}
			raw, _ := json.Marshal(job)
			driver := &DownloadWorkerJobs{profile: p}
			_, _, err := driver.checkedJob(i, raw)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("native Job check %s: %v", mode, err)
			}
		})
	}
}
