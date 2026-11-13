package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Actual chart output is checked against the provider's exact command/mount
// consumer. This is source composition, not Seaweed runtime qualification.
func TestSmallSeaweedHelmUsesExactProviderAndRetainedStorage(t *testing.T) {
	helm, e := exec.LookPath("helm")
	if e != nil {
		t.Skip("Helm is required")
	}
	for _, mode := range []string{"bundled", "external"} {
		t.Run(mode, func(t *testing.T) {
			provider := "seaweedfs"
			if mode == "external" {
				provider = "external"
			}
			values := smallServicesHelmValues(map[string]any{"objectStore": map[string]any{"provider": provider}})
			raw, e := json.Marshal(values)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "public-values.json")
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, end := context.WithTimeout(t.Context(), 15*time.Second)
			defer end()
			output, e := exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", path).CombinedOutput()
			if e != nil {
				t.Fatalf("actual chart render: %v\n%s", e, output)
			}
			var st *apps.StatefulSet
			var service *core.Service
			var pvc *core.PersistentVolumeClaim
			var config *core.ConfigMap
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
			for {
				var doc json.RawMessage
				e = decoder.Decode(&doc)
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				var head struct {
					Kind     string
					Metadata struct{ Name string }
				}
				if json.Unmarshal(doc, &head) != nil {
					t.Fatal("chart JSON")
				}
				switch {
				case head.Kind == "StatefulSet" && head.Metadata.Name == "trial-objectstore":
					st = &apps.StatefulSet{}
					e = json.Unmarshal(doc, st)
				case head.Kind == "Service" && head.Metadata.Name == "trial-objectstore":
					service = &core.Service{}
					e = json.Unmarshal(doc, service)
				case head.Kind == "PersistentVolumeClaim" && head.Metadata.Name == "trial-objectstore-data":
					pvc = &core.PersistentVolumeClaim{}
					e = json.Unmarshal(doc, pvc)
				case head.Kind == "ConfigMap" && head.Metadata.Name == "trial-objectstore-config":
					config = &core.ConfigMap{}
					e = json.Unmarshal(doc, config)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if mode == "external" {
				if st != nil || service != nil || pvc != nil || config != nil {
					t.Fatal("external choice installed bundled provider")
				}
				return
			}
			if st == nil || service == nil || config == nil || len(st.Spec.Template.Spec.Containers) != 1 || st.Spec.Replicas == nil || *st.Spec.Replicas != 1 {
				t.Fatal("missing bounded provider")
			}
			c := st.Spec.Template.Spec.Containers[0]
			if c.Image != "chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0" || !slices.Equal(c.Command, []string{"/usr/bin/weed"}) || !slices.Equal(c.Args, providerconfig.SeaweedServerArgs()) {
				t.Fatal("chart command disagrees with provider consumer")
			}
			ps := st.Spec.Template.Spec
			if ps.AutomountServiceAccountToken == nil || *ps.AutomountServiceAccountToken || ps.SecurityContext == nil || ps.SecurityContext.RunAsNonRoot == nil || !*ps.SecurityContext.RunAsNonRoot || ps.SecurityContext.RunAsUser == nil || *ps.SecurityContext.RunAsUser != 65532 || c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
				t.Fatal("provider lost restricted process confinement")
			}
			if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8333 || len(c.Env) != 0 || len(c.EnvFrom) != 0 {
				t.Fatal("extra endpoint or ambient credentials")
			}
			if config.Data["filer.toml"] != "[leveldb2]\nenabled = true\ndir = \"/data/filerldb2\"\n" {
				t.Fatal("filer metadata not explicitly persistent")
			}
			mounts := map[string]core.VolumeMount{}
			for _, m := range c.VolumeMounts {
				mounts[m.Name] = m
			}
			for _, v := range ps.Volumes {
				switch v.Name {
				case "data":
					want := "trial-objectstore-data"
					if v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != want || mounts[v.Name].MountPath != "/data" {
						t.Fatal("provider storage replaced or incomplete")
					}
				case "iam":
					m := mounts[v.Name]
					if v.Secret == nil || v.Secret.SecretName != "trial-objectstore-iam" || len(v.Secret.Items) != 1 || v.Secret.Items[0].Key != "s3.json" || m.MountPath != "/run/asservat/objectstore-iam" || m.SubPath != "" || m.SubPathExpr != "" || !m.ReadOnly {
						t.Fatal("IAM projection cannot be consumed by reload")
					}
				case "tls":
					if v.Secret == nil || v.Secret.SecretName != "trial-objectstore-state" || len(v.Secret.Items) != 2 {
						t.Fatal("TLS not bound to retained private material")
					}
				}
			}
			if pvc == nil || pvc.Annotations["helm.sh/resource-policy"] != "keep" || pvc.Spec.Resources.Requests.Storage().String() != "32Gi" {
				t.Fatal("new persistent state not retained")
			}
		})
	}
}
