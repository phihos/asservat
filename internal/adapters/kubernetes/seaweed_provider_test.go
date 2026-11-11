package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func swID(n string) string { return "00000000-0000-4000-8000-00000000000" + n }
func seaweedTestConfig(t *testing.T) ([]byte, []byte) {
	t.Helper()
	admin, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: swID("1")})
	if e != nil {
		t.Fatal(e)
	}
	a, e := providerconfig.CompileSeaweedStorage(admin, nil)
	if e != nil {
		t.Fatal(e)
	}
	c, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "regional-write", ScopeID: swID("2")})
	if e != nil {
		t.Fatal(e)
	}
	b, e := providerconfig.CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: c, Bucket: "evidence", InstallationID: swID("1"), ClusterID: swID("2")}})
	if e != nil {
		t.Fatal(e)
	}
	return a.Config, b.Config
}
func TestSeaweedReloadConsumesProjectionAfterExactCAS(t *testing.T) {
	for _, bad := range []string{"", "replacement", "subpath", "changed-key", "unknown-cas"} {
		t.Run(bad, func(t *testing.T) {
			before, after := seaweedTestConfig(t)
			defer clear(before)
			defer clear(after)
			target := contracts.SeaweedProviderTarget{InstallationID: swID("1"), Namespace: "setup", StatefulSet: contracts.WorkerObjectReference{Name: "install-objectstore", UID: swID("3")}, Pod: contracts.WorkerObjectReference{Name: "install-objectstore-0", UID: swID("4")}, Config: contracts.WorkerObjectReference{Name: "install-objectstore-iam", UID: swID("5")}, Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64), ExpectedArgs: providerconfig.SeaweedServerArgs()}
			st := apps.StatefulSet{ObjectMeta: meta.ObjectMeta{Name: target.StatefulSet.Name, UID: types.UID(target.StatefulSet.UID)}}
			pod := core.Pod{ObjectMeta: meta.ObjectMeta{Name: target.Pod.Name, UID: types.UID(target.Pod.UID), OwnerReferences: []meta.OwnerReference{{Kind: "StatefulSet", Name: st.Name, UID: st.UID, Controller: ptr.To(true)}}}, Spec: core.PodSpec{Containers: []core.Container{{Name: "seaweed", Image: target.Image, Command: []string{"/usr/bin/weed"}, Args: target.ExpectedArgs, VolumeMounts: []core.VolumeMount{{Name: "iam", MountPath: "/run/asservat/objectstore-iam", ReadOnly: true}}}}, Volumes: []core.Volume{{Name: "iam", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: target.Config.Name, Items: []core.KeyToPath{{Key: "s3.json", Path: "s3.json"}}}}}}}, Status: core.PodStatus{Phase: core.PodRunning, ContainerStatuses: []core.ContainerStatus{{Name: "seaweed", Ready: true, ImageID: target.Image, State: core.ContainerState{Running: &core.ContainerStateRunning{StartedAt: meta.NewTime(time.Now())}}}}}}
			secret := core.Secret{ObjectMeta: meta.ObjectMeta{Name: target.Config.Name, UID: types.UID(target.Config.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"s3.json": bytes.Clone(before)}}
			if bad == "replacement" {
				pod.UID = types.UID(swID("6"))
			}
			if bad == "subpath" {
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "s3.json"
			}
			if bad == "changed-key" {
				after = bytes.ReplaceAll(after, []byte("\"Admin\""), []byte("\"AdminBroken\""))
			}
			puts, execs := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.Contains(r.URL.Path, "/statefulsets/"):
					_ = json.NewEncoder(w).Encode(st)
				case strings.Contains(r.URL.Path, "/pods/"):
					_ = json.NewEncoder(w).Encode(pod)
				case strings.Contains(r.URL.Path, "/secrets/"):
					if r.Method == http.MethodPut {
						puts++
						var next core.Secret
						if json.NewDecoder(r.Body).Decode(&next) != nil || next.UID != secret.UID || next.ResourceVersion != "1" {
							t.Error("lost original CAS")
						}
						if bad == "unknown-cas" {
							http.Error(w, "unknown", 500)
							return
						}
						secret = next
						secret.ResourceVersion = "2"
					}
					_ = json.NewEncoder(w).Encode(secret)
				default:
					t.Error("unexpected API path")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
			provider, e := NewSeaweedProvider(config, target)
			if e != nil {
				t.Fatal(e)
			}
			provider.exec = func(ctx context.Context, input []byte) error {
				execs++
				h := sha256.Sum256(after)
				if string(input) != hex.EncodeToString(h[:])+"\n" || !bytes.Equal(secret.Data["s3.json"], after) {
					t.Error("reload before desired config CAS")
				}
				return nil
			}
			e = provider.Reload(context.Background(), after)
			if bad == "" {
				if e != nil || puts != 1 || execs != 1 {
					t.Fatalf("expected one CAS and reload, puts=%d execs=%d err=%v", puts, execs, e)
				}
			} else if e == nil || execs != 0 {
				t.Fatalf("invalid transition reached exec: puts=%d execs=%d err=%v", puts, execs, e)
			}
		})
	}
}
func TestSeaweedReloadCommandDoesNotPutPrivateInputInArguments(t *testing.T) {
	if !strings.Contains(seaweedReloadScript, "IFS= read -r expected") || !strings.Contains(seaweedReloadScript, "sha256sum /run/asservat/objectstore-iam/s3.json") || !strings.Contains(seaweedReloadScript, "exec /bin/kill -HUP 1") || strings.Contains(seaweedReloadScript, "echo") {
		t.Fatal("fixed private projection handshake changed")
	}
}
