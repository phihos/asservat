package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// installedReleaseChange runs the product installer-upgrade command in image
// mode (ADR-227) as the installer runner account, in a Pod of the target
// image, and requires the release record at revision, settled on image, with
// both hub Deployments rolled out to it.
func installedReleaseChange(t *testing.T, ctx context.Context, api kubernetes.Interface, desired contracts.InitialBootstrap, installation, image string, revision int64) {
	t.Helper()
	started := time.Now()
	namespace := desired.BootstrapNamespace
	inputs := desired.Name + "-upgrade-input"
	if _, err := api.CoreV1().Secrets(namespace).Get(ctx, inputs, meta.GetOptions{}); apierrors.IsNotFound(err) {
		// The fixture removes operator-ddl after installation; its DDL role is
		// the same synthetic schema owner as the retained producer credential.
		ddl, e := api.CoreV1().Secrets(namespace).Get(ctx, "operator-producer", meta.GetOptions{})
		if e != nil || len(ddl.Data["postgres-administrator.json"]) == 0 {
			t.Fatal("operator DDL credential", e)
		}
		endpoint, e := json.Marshal(desired.Postgres)
		if e != nil {
			t.Fatal(e)
		}
		secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: inputs}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"postgres-endpoint.json": endpoint, "postgres-ddl.json": ddl.Data["postgres-administrator.json"]}}
		if _, e = api.CoreV1().Secrets(namespace).Create(ctx, secret, meta.CreateOptions{}); e != nil {
			t.Fatal("upgrade inputs", e)
		}
		t.Cleanup(func() {
			c, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			_ = api.CoreV1().Secrets(namespace).Delete(c, inputs, meta.DeleteOptions{})
		})
	} else if err != nil {
		t.Fatal("upgrade inputs", err)
	}
	field := func(path string) *core.EnvVarSource {
		return &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: path}}
	}
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: fmt.Sprintf("%s-upgrade-%d", desired.Name, revision), Labels: map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "installer-upgrade"}},
		Spec: core.PodSpec{ServiceAccountName: desired.Name + "-bootstrap-runner", AutomountServiceAccountToken: ptr.To(true), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyNever, ActiveDeadlineSeconds: ptr.To(int64(900)), TerminationGracePeriodSeconds: ptr.To(int64(15)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Volumes:         []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: inputs, DefaultMode: ptr.To(int32(0o440))}}}},
			Containers: []core.Container{{Name: "upgrade", Image: image, ImagePullPolicy: core.PullIfNotPresent,
				Command:         []string{"/asservat", "installer-upgrade", "--inputs", "/run/asservat/upgrade", "--image", image, "--namespace", desired.TargetNamespace, "--installation", installation},
				Env:             []core.EnvVar{{Name: contracts.InstallerUpgradePodNameEnvironment, ValueFrom: field("metadata.name")}, {Name: contracts.InstallerUpgradePodNamespaceEnvironment, ValueFrom: field("metadata.namespace")}},
				VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: "/run/asservat/upgrade", ReadOnly: true}},
				SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			}}}}
	created, err := api.CoreV1().Pods(namespace).Create(ctx, pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal("installer-upgrade Pod", err)
	}
	logs := func() string {
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		raw, _ := api.CoreV1().Pods(namespace).GetLogs(created.Name, &core.PodLogOptions{Container: "upgrade", LimitBytes: ptr.To(int64(65536))}).DoRaw(c)
		return string(bytes.TrimSpace(raw))
	}
	defer func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		_ = api.CoreV1().Pods(namespace).Delete(c, created.Name, meta.DeleteOptions{})
	}()
	for until := time.Now().Add(9 * time.Minute); ; time.Sleep(2 * time.Second) {
		current, e := api.CoreV1().Pods(namespace).Get(ctx, created.Name, meta.GetOptions{})
		if e == nil && current.Status.Phase == core.PodSucceeded {
			break
		}
		if e == nil && current.Status.Phase == core.PodFailed || time.Now().After(until) {
			installedProcessDiagnostics(t, ctx, api, desired.TargetNamespace, append(kube.HubDeploymentNamesList(installation), kube.ReleaseFollowerNames(installation)...)...)
			t.Fatal("installer-upgrade did not succeed", e, logs())
		}
	}
	t.Logf("installed journey: installer-upgrade to revision %d took %s: %s", revision, time.Since(started).Round(time.Second), logs())
	record, err := api.CoreV1().ConfigMaps(desired.TargetNamespace).Get(ctx, contracts.ReleaseRecordName(installation), meta.GetOptions{})
	if err != nil {
		t.Fatal("release record", err)
	}
	r, err := contracts.DecodeReleaseRecord(bytes.NewBufferString(record.Data[contracts.ReleaseRecordFile]))
	if err != nil || r.Revision != revision || r.Image != image || r.Previous != "" || r.Original != desired.Image {
		t.Fatal("release record not settled on the image", err, record.Data[contracts.ReleaseRecordFile])
	}
	// Phase 3: the installed journey enables all three followers (key service,
	// publisher, federation), so each must exist and follow the release too.
	for _, name := range append(kube.HubDeploymentNamesList(installation), kube.ReleaseFollowerNames(installation)...) {
		d, e := api.AppsV1().Deployments(desired.TargetNamespace).Get(ctx, name, meta.GetOptions{})
		if e != nil || d.Spec.Template.Spec.Containers[0].Image != image || !kube.HubDeploymentSettled(*d) {
			t.Fatal("hub Deployment not settled on the image", name, e)
		}
	}
}
