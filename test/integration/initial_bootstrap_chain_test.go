package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

func initialBootstrapAdminPoolConfig(dsn string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// Only the installed continuation's sequential observer uses one reserved
	// superuser slot. Other bootstrap modes deliberately hold an admin lock
	// while observing through another connection and retain their old pool.
	if os.Getenv("ASSERVAT_INSTALLER_CONTINUATION") == "1" {
		config.MaxConns, config.MinConns = 1, 0
	}
	return config, nil
}

func TestInitialBootstrapAdminPoolKeepsBlockingModes(t *testing.T) {
	const dsn = "postgres://fixture@127.0.0.1/fixture?sslmode=disable"
	original, err := pgxpool.ParseConfig(dsn)
	if err != nil || original.MaxConns < 2 {
		t.Fatal("original component pool must support blocking lock tests", err)
	}
	for _, mode := range []string{"", "1"} {
		t.Run("installed="+mode, func(t *testing.T) {
			t.Setenv("ASSERVAT_INSTALLER_CONTINUATION", mode)
			got, err := initialBootstrapAdminPoolConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			want := original.MaxConns
			if mode == "1" {
				want = 1
			}
			if got.MaxConns != want || got.MinConns != original.MinConns {
				t.Fatal("component and installed observer pool profiles differ", got.MaxConns, got.MinConns)
			}
		})
	}
}

func initialBootstrapChainProvider(t *testing.T, ctx context.Context, f fixture, d contracts.InitialBootstrap) string {
	if ctx.Err() != nil {
		t.Fatal("original provider setup deadline expired")
	}
	t.Helper()
	profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: d.Name + "-provider-material", UID: custodyID()}, IssuerPolicy: d.Providers.IssuerPolicy, WrapRole: d.Providers.WrapRole, WrapPolicy: d.Providers.WrapPolicy, UnwrapRole: d.Providers.UnwrapRole, UnwrapPolicy: d.Providers.UnwrapPolicy}
	// Material UID is required structurally by the policy builder but is not a
	// policy input or passed to product. The real producer obtains its own UID.
	policies, err := kms.InitialProviderPolicies(profile, d.KeyService.AuditMount, d.KeyService.AuditKey)
	if err != nil {
		t.Fatal(err)
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+d.KeyService.AuditMount, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", d.KeyService.AuditMount+"/keys/"+d.KeyService.AuditKey, map[string]any{"type": "aes256-gcm96"}, 200)
	for name, policy := range policies {
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
	}
	for role, policy := range map[string]string{d.Providers.WrapRole: d.Providers.WrapPolicy, d.Providers.UnwrapRole: d.Providers.UnwrapPolicy} {
		request(t, f.KMS, "synthetic-root", "auth/token/roles/"+role, map[string]any{"allowed_policies": []string{policy}, "orphan": false, "renewable": false, "token_type": "service", "token_no_default_policy": true, "token_explicit_max_ttl": 900}, 204)
	}
	issued := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{d.Providers.IssuerPolicy}, "no_default_policy": true, "no_parent": false, "renewable": false, "type": "service", "ttl": "15m", "explicit_max_ttl": "15m"}, 200)
	return issued["auth"].(map[string]any)["client_token"].(string)
}

func initialBootstrapChainPod(d contracts.InitialBootstrap, name string, replay bool) *core.Pod {
	mode := int32(0440)
	public := core.VolumeProjection{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: "operator-bootstrap"}, Items: []core.KeyToPath{{Key: "bootstrap.json", Path: "bootstrap.json"}}}}
	token := core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "administrator-token", Audience: d.ProbeAudience, ExpirationSeconds: ptr.To(int64(600))}}
	inputs := func(secret string) core.VolumeSource {
		sources := []core.VolumeProjection{public, token}
		if !replay {
			sources = append(sources, core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: secret}}})
		}
		return core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: &mode, Sources: sources}}
	}
	memory := resource.MustParse("8Mi")
	volumes := []core.Volume{
		{Name: "scratch", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory, SizeLimit: &memory}}},
		{Name: "producer-input", VolumeSource: inputs("operator-producer")},
		{Name: "retirement-input", VolumeSource: inputs("operator-retirement")},
	}
	if !replay {
		volumes = append(volumes, core.Volume{Name: "ddl-input", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "operator-ddl", DefaultMode: &mode}}})
	}
	scratch := core.VolumeMount{Name: "scratch", MountPath: bootstrap.InitialBootstrapScratchRoot}
	container := func(name, command string, mounts ...core.VolumeMount) core.Container {
		return core.Container{Name: name, Image: d.Image, ImagePullPolicy: core.PullNever, Command: []string{"/asservat", command}, VolumeMounts: mounts, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("20m"), core.ResourceMemory: resource.MustParse("32Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("256Mi")}}}
	}
	producer := container("produce", "initial-bootstrap", scratch, core.VolumeMount{Name: "producer-input", MountPath: bootstrap.InitialBootstrapRoot, ReadOnly: true})
	schema := container("schema", "initial-bootstrap-schema", core.VolumeMount{Name: "scratch", MountPath: bootstrap.InitialSchemaRoot, SubPath: "projection/schema", ReadOnly: true})
	if !replay {
		schema.VolumeMounts = append(schema.VolumeMounts, core.VolumeMount{Name: "ddl-input", MountPath: bootstrap.InitialBootstrapSchemaPrivateRoot, ReadOnly: true})
	}
	prepare := container("prepare", "initial-bootstrap-prepare", core.VolumeMount{Name: "scratch", MountPath: bootstrap.InitialPreparerRoot, SubPath: "projection/preparer", ReadOnly: true})
	retire := container("retire", "initial-bootstrap-retire", scratch, core.VolumeMount{Name: "retirement-input", MountPath: bootstrap.InitialBootstrapRoot, ReadOnly: true})
	return &core.Pod{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: d.BootstrapNamespace}, Spec: core.PodSpec{ServiceAccountName: "trusted-runner", AutomountServiceAccountToken: ptr.To(false), RestartPolicy: core.RestartPolicyNever, ActiveDeadlineSeconds: ptr.To(int64(300)), TerminationGracePeriodSeconds: ptr.To(int64(15)), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), FSGroupChangePolicy: ptr.To(core.FSGroupChangeOnRootMismatch), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Volumes: volumes, InitContainers: []core.Container{producer, schema, prepare}, Containers: []core.Container{retire}}}
}

func initialBootstrapChainRun(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, name string, replay bool) *core.Pod {
	t.Helper()
	pod, err := api.CoreV1().Pods(d.BootstrapNamespace).Create(ctx, initialBootstrapChainPod(d, name, replay), meta.CreateOptions{})
	if err != nil {
		t.Fatal("actual Restricted runner admission", err)
	}
	original := pod.UID
	limit, stop := context.WithTimeout(ctx, 310*time.Second)
	defer stop()
	defer func() {
		if !t.Failed() {
			return
		}
		diagnostics, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		current, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(diagnostics, name, meta.GetOptions{})
		if e != nil || current.UID != original {
			return
		}
		for _, status := range append(current.Status.InitContainerStatuses, current.Status.ContainerStatuses...) {
			// Only fixed product errors are emitted; never log projected file contents.
			logs, e := api.CoreV1().Pods(d.BootstrapNamespace).GetLogs(name, &core.PodLogOptions{Container: status.Name, LimitBytes: ptr.To(int64(8192))}).DoRaw(diagnostics)
			if e == nil {
				t.Log("runner", status.Name, "phase", current.Status.Phase, "output", string(logs))
			}
		}
	}()
	for {
		if limit.Err() != nil {
			t.Fatal("actual fixed-command runner deadline", limit.Err())
		}
		pod, err = api.CoreV1().Pods(d.BootstrapNamespace).Get(limit, name, meta.GetOptions{})
		if err != nil || pod.UID != original {
			t.Fatal("original runner lost/replaced", err)
		}
		if pod.Status.Phase == core.PodFailed {
			t.Fatal("actual fixed-command runner failed")
		}
		if pod.Status.Phase == core.PodSucceeded {
			break
		}
		select {
		case <-limit.Done():
			t.Fatal("runner did not finish original interval")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if len(pod.Status.InitContainerStatuses) != 3 || len(pod.Status.ContainerStatuses) != 1 {
		t.Fatal("runner phase dispositions incomplete")
	}
	for _, s := range append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...) {
		if s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 || s.RestartCount != 0 || !strings.HasSuffix(s.ImageID, strings.Split(d.Image, "@")[1]) {
			t.Fatal("runner used wrong image/restarted/failed phase", s.Name)
		}
	}
	return pod
}

func initialBootstrapChainImage(t *testing.T, p *core.Pod, image string) {
	t.Helper()
	if p == nil || p.Status.Phase != core.PodSucceeded || len(p.Status.ContainerStatuses) != 1 {
		t.Fatal("original activation did not succeed")
	}
	s := p.Status.ContainerStatuses[0]
	parts := strings.Split(image, "@")
	if len(parts) != 2 || !strings.HasSuffix(s.ImageID, parts[1]) || s.RestartCount != 0 || s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 {
		t.Fatal("wrong original activation executable/image")
	}
	t.Log("original activation", p.UID, "image", s.ImageID, "exit", s.State.Terminated.ExitCode)
}

func initialBootstrapChainState(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, original bootstrapRetirementEvidence) (contracts.InitialBootstrapState, contracts.InitialPreparer, contracts.InitialPreparationRoot) {
	t.Helper()
	seed, err := api.CoreV1().Secrets(d.BootstrapNamespace).Get(ctx, d.Name+"-bootstrap-state", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state := original.State
	for _, b := range seed.Data {
		defer clear(b)
	}
	if seed.Immutable == nil || !*seed.Immutable || len(seed.Data) != 1 || string(seed.Data["retired"]) != "true" || string(seed.UID) != original.UID || seed.ResourceVersion == original.ResourceVersion || state.SeedUID != string(seed.UID) || state.Projection == nil || state.PassiveHistory == nil || state.PassiveHistory.Receipt == nil {
		t.Fatal("actual original seed/locator incomplete", err)
	}
	projection, err := api.CoreV1().ConfigMaps(d.BootstrapNamespace).Get(ctx, state.Projection.Name, meta.GetOptions{})
	if err != nil || string(projection.UID) != state.Projection.UID {
		t.Fatal("original public projection replaced", err)
	}
	c, err := contracts.DecodeInitialPreparer(strings.NewReader(projection.Data["deployment.json"]))
	if err != nil {
		t.Fatal(err)
	}
	rootCM, err := api.CoreV1().ConfigMaps(d.BootstrapNamespace).Get(ctx, c.Plan.RootName, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	root, err := contracts.DecodeInitialPreparationRoot(strings.NewReader(rootCM.Data["root.json"]))
	if err != nil || root.RootUID != string(rootCM.UID) || root.InstallationID != state.InstallationID || root.RequestID != state.RequestID {
		t.Fatal("actual original preparation root differs", err)
	}
	return state, c, root
}

func initialBootstrapChainAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *s3.Client, httpClient *http.Client, f fixture, d contracts.InitialBootstrap, state contracts.InitialBootstrapState, root contracts.InitialPreparationRoot) {
	t.Helper()
	var recordJSON, receiptJSON []byte
	var activated, blocked bool
	if err := admin.QueryRow(ctx, "SELECT record_json,audit_receipt_json,activated_at IS NOT NULL FROM fleet_initial_activation WHERE installation_id=$1", state.InstallationID).Scan(&recordJSON, &receiptJSON, &activated); err != nil || !activated {
		t.Fatal("actual independent activation absent", err)
	}
	if err := admin.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_current_trust WHERE installation_id=$1", state.InstallationID).Scan(&blocked); err != nil || blocked {
		t.Fatal("actual incarnation not activated", err)
	}
	var record audit.InitialInstallation
	var receipt audit.Receipt
	if json.Unmarshal(recordJSON, &record) != nil || json.Unmarshal(receiptJSON, &receipt) != nil || receipt.Version == "" || receipt.Version == "null" || !record.Valid() || !receipt.ValidInitialInstallation(state.InstallationID, record.Claim.ID) || root.Activation.Handover.Cleanup.ActivatedClaimID != record.Claim.ID || record.Scope.ClusterID != state.ClusterID {
		t.Fatal("original encrypted activation scope invalid")
	}
	object, err := store.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.AuditStore.Bucket, Key: &receipt.Key, VersionId: &receipt.Version})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(io.LimitReader(object.Body, (128<<10)+1))
	object.Body.Close()
	defer clear(ciphertext)
	if err != nil || len(ciphertext) > 128<<10 || int64(len(ciphertext)) != receipt.Bytes || sha256.Sum256(ciphertext) != [32]byte(receipt.SHA256) {
		t.Fatal("actual immutable audit bytes differ")
	}
	opener, err := kms.NewOpener(d.KeyService.Endpoint, "synthetic-root", d.KeyService.AuditMount, d.KeyService.AuditKey, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if err = framed.VerifyInitialInstallation(ctx, opener, record, ciphertext); err != nil {
		t.Fatal("independent retained audit cannot verify", err)
	}
}

func initialBootstrapChainCleanup(t *testing.T, api kubernetes.Interface, d contracts.InitialBootstrap, bootstrapUID, roleUID, bindingUID types.UID) {
	if keepFailedFixture(t) {
		return
	}
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 60*time.Second)
	defer end()
	installation := ""
	if seed, err := api.CoreV1().Secrets(d.BootstrapNamespace).Get(ctx, d.Name+"-bootstrap-state", meta.GetOptions{}); err == nil {
		if state, decodeErr := contracts.DecodeInitialBootstrapState(bytes.NewReader(seed.Data["state.json"])); decodeErr == nil {
			installation = state.InstallationID
		} else if locator, decodeErr := contracts.DecodeInitialBootstrapPassiveLocator(strings.NewReader(seed.Annotations["asservat.io/bootstrap-passive-history"])); decodeErr == nil && locator.SeedUID == string(seed.UID) {
			installation = locator.InstallationID
		}
		for _, data := range seed.Data {
			clear(data)
		}
	}
	// Stop and join only this test's runners before removing public protections.
	for _, name := range []string{"bootstrap-first", "bootstrap-replay", d.Name + "-bootstrap"} {
		p, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
		if e == nil {
			e = api.CoreV1().Pods(d.BootstrapNamespace).Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}})
		}
		if e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned runner cleanup", e)
			return
		}
		for ctx.Err() == nil {
			current, readErr := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
			if apierrors.IsNotFound(readErr) {
				break
			}
			if readErr != nil || p == nil || current.UID != p.UID {
				t.Error("original runner cleanup observation failed", readErr)
				return
			}
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
		if ctx.Err() != nil {
			t.Error("original runner cleanup did not join")
			return
		}
	}
	for _, name := range []string{d.BootstrapNamespace + "-" + d.Name + "-bootstrap", d.BootstrapNamespace + "-" + d.Name + "-copy-tombstone", d.BootstrapNamespace + "-" + d.Name + "-continuity", d.TargetNamespace + "-" + d.Name + "-staging", d.TargetNamespace + "-" + d.Name + "-witness", d.TargetNamespace + "-" + d.Name + "-fleet", d.TargetNamespace + "-" + d.Name + "-workload"} {
		b, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, name, meta.GetOptions{})
		if e == nil {
			e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &b.UID}})
		}
		if e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned guard binding cleanup", e)
		}
		p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, name, meta.GetOptions{})
		if e == nil {
			e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}})
		}
		if e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned guard cleanup", e)
		}
	}
	for _, name := range []string{d.TargetNamespace, d.BootstrapNamespace} {
		n, e := api.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
		if apierrors.IsNotFound(e) {
			continue
		}
		if e != nil {
			t.Error(e)
			continue
		}
		if name == d.TargetNamespace && (installation == "" || n.Annotations["asservat.io/installation-id"] != installation) {
			t.Error("refuse unbound target namespace cleanup")
			continue
		}
		if name == d.BootstrapNamespace && n.UID != bootstrapUID {
			t.Error("refuse replaced bootstrap namespace")
			continue
		}
		for {
			e = api.CoreV1().Namespaces().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &n.UID}})
			if e == nil || apierrors.IsNotFound(e) {
				break
			}
			if !initialBootstrapChainRemovedGuard(e, d) || ctx.Err() != nil {
				t.Error("owned namespace deletion", e)
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
		for ctx.Err() == nil {
			_, e = api.CoreV1().Namespaces().Get(ctx, name, meta.GetOptions{})
			if apierrors.IsNotFound(e) {
				break
			}
			if e != nil {
				t.Error(e)
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	name := d.BootstrapNamespace + "-administrator"
	if bindingUID != "" {
		if e := api.RbacV1().ClusterRoleBindings().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &bindingUID}}); e != nil && !apierrors.IsNotFound(e) {
			t.Error(e)
		}
	}
	if roleUID != "" {
		if e := api.RbacV1().ClusterRoles().Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &roleUID}}); e != nil && !apierrors.IsNotFound(e) {
			t.Error(e)
		}
	}
	if ctx.Err() != nil {
		t.Error("owned bootstrap cleanup did not converge")
	}
}

func initialBootstrapChainRemovedGuard(err error, d contracts.InitialBootstrap) bool {
	for _, name := range []string{d.BootstrapNamespace + "-" + d.Name + "-bootstrap", d.BootstrapNamespace + "-" + d.Name + "-copy-tombstone", d.BootstrapNamespace + "-" + d.Name + "-continuity", d.TargetNamespace + "-" + d.Name + "-staging", d.TargetNamespace + "-" + d.Name + "-witness", d.TargetNamespace + "-" + d.Name + "-fleet", d.TargetNamespace + "-" + d.Name + "-workload"} {
		if initialPreparerCleanupDenial(err, name) || initialBootstrapGuardDenial(err, name) {
			return true
		}
	}
	return false
}

// installedClusterCount is the hub plus its workload clusters: two for the
// focused runs that use one workload cluster, three otherwise.
func installedClusterCount() int {
	if f := installedJourneyFocus(); f == "restart" || f == "journey" || f == "browser" || f == "upgrade" || f == "policy" || f == "alert" || f == "logresource" || f == "chain" || f == "share" || f == "approved-recording" || f == "manual-logs" || f == "manual-syscall" || f == "manual-arguments" || f == "manual-mixed" || f == "manual-raw" || f == "manual-http" || f == "manual-peers" || installedProfileFocus() || f == "native-paced" || f == "policy-recording" || f == "policy-arguments" || f == "policy-profile" || installedOngoingFocus() || f == "journey-store-failure" || f == "journey-start-failure" || f == "retention-shortening" || f == "early-erasure" || f == "processing-workload" || f == "privacy-inventory" || f == "share-retirement" {
		return 2
	}
	return 3
}
