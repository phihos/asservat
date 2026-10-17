package kubernetes

import (
	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	scheduling "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"time"
)

var errWorkerJobMissing = errors.New("download worker job missing")

const DownloadWorkerTokenPath = contracts.WorkerTokenPath

const workerLabel = "asservat.io/download-worker"

type DownloadWorkerJobs struct {
	client        *PermissionClient
	profile       value.DownloadWorkerProfile
	configuration app.WorkerConfigurationGuard
}

var _ app.DownloadWorkerJobs = (*DownloadWorkerJobs)(nil)

func NewDownloadWorkerJobs(c *PermissionClient, p value.DownloadWorkerProfile, configuration app.WorkerConfigurationGuard) (*DownloadWorkerJobs, error) {
	if c == nil || configuration == nil || !p.Valid() || c.clusterID != p.ClusterID || c.control.Name != p.Namespace || c.control.UID != p.NamespaceUID || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(p.ServiceAccount)) != 0 || len(validation.IsDNS1123Subdomain(p.ControlConfig)) != 0 || len(validation.IsDNS1123Subdomain(p.PriorityClass)) != 0 {
		return nil, artifact.ErrInvalid
	}
	for _, name := range p.ImagePullSecrets {
		if name != "" && len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, artifact.ErrInvalid
		}
	}
	if p.StoreCredentialSecret != "" && len(validation.IsDNS1123Subdomain(p.StoreCredentialSecret)) != 0 {
		return nil, artifact.ErrInvalid
	}
	return &DownloadWorkerJobs{c, p, configuration}, nil
}
func workerJSONEqual(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}
func WorkerControlDigest(data map[string]string) (artifact.Digest, error) {
	return mtls.WorkerControlDigest(data)
}
func (s *DownloadWorkerJobs) sources(ctx context.Context) error {
	p := s.profile
	ns, e := s.client.namespace(ctx, s.client.control)
	if e != nil || ns.Deleting || ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		return artifact.ErrInvalid
	}
	b, e := s.client.raw(ctx, "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount, nil)
	if e != nil {
		return artifact.ErrInvalid
	}
	defer clear(b)
	var sa core.ServiceAccount
	if json.Unmarshal(b, &sa) != nil || sa.APIVersion != "v1" || sa.Kind != "ServiceAccount" || sa.Name != p.ServiceAccount || sa.Namespace != p.Namespace || string(sa.UID) != p.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return artifact.ErrInvalid
	}
	b, e = s.client.raw(ctx, "/api/v1/namespaces/"+p.Namespace+"/configmaps/"+p.ControlConfig, nil)
	if e != nil {
		return artifact.ErrInvalid
	}
	defer clear(b)
	var cm core.ConfigMap
	if json.Unmarshal(b, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Name != p.ControlConfig || cm.Namespace != p.Namespace || string(cm.UID) != p.ControlConfigUID || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.BinaryData) > 0 {
		return artifact.ErrInvalid
	}
	d, e := WorkerControlDigest(cm.Data)
	if e != nil || d != p.ControlDigest {
		return artifact.ErrInvalid
	}
	control, e := mtls.ParseWorkerControl([]byte(cm.Data["worker.json"]))
	if e != nil || control.InstallationID != p.InstallationID || control.ClusterID != p.ClusterID {
		return artifact.ErrInvalid
	}
	if (control.Native() == nil) != (p.StoreCredentialSecret == "") {
		return artifact.ErrInvalid
	}
	if native := control.Native(); native != nil {
		settings := native.Settings()
		if settings.StoreCredentialSecretName != p.StoreCredentialSecret || settings.StoreCredentialSecretUID != p.StoreCredentialSecretUID {
			return artifact.ErrInvalid
		}
		if e = checkWorkerStoreSecret(ctx, s.client, p); e != nil {
			return e
		}
	}
	if _, _, e = control.Roots(s.client.now()); e != nil {
		return artifact.ErrInvalid
	}
	b, e = s.client.raw(ctx, "/apis/scheduling.k8s.io/v1/priorityclasses/"+p.PriorityClass, nil)
	if e != nil {
		return artifact.ErrInvalid
	}
	defer clear(b)
	var priority scheduling.PriorityClass
	if json.Unmarshal(b, &priority) != nil || priority.APIVersion != "scheduling.k8s.io/v1" || priority.Kind != "PriorityClass" || priority.Name != p.PriorityClass || priority.Namespace != "" || string(priority.UID) != p.PriorityClassUID || priority.DeletionTimestamp != nil || priority.Value != 0 || priority.GlobalDefault || priority.PreemptionPolicy == nil || *priority.PreemptionPolicy != core.PreemptNever {
		return artifact.ErrInvalid
	}
	return nil
}
func workerJob(i value.DownloadWorkerIntent) *batch.Job {
	p := i.Profile
	no, yes := false, true
	uid, grace, tokenLife, mode := int64(65532), int64(5), int64(600), int32(0440)
	zero, one := int32(0), int32(1)
	duration := int64(i.RunUntil.Sub(i.CreatedAt) / time.Second)
	completion, replacement, preempt := batch.NonIndexedCompletion, batch.Failed, core.PreemptNever
	cpu, mem := *resource.NewMilliQuantity(p.CPUMillis, resource.DecimalSI), *resource.NewQuantity(p.MemoryBytes, resource.BinarySI)
	resources := core.ResourceList{core.ResourceCPU: cpu, core.ResourceMemory: mem, core.ResourceEphemeralStorage: resource.MustParse("4Mi")}
	labels := map[string]string{workerLabel: i.ID}
	pod := core.PodSpec{
		PriorityClassName:  p.PriorityClass,
		ServiceAccountName: p.ServiceAccount, DeprecatedServiceAccount: p.ServiceAccount, AutomountServiceAccountToken: &no,
		RestartPolicy: core.RestartPolicyNever, TerminationGracePeriodSeconds: &grace, DNSPolicy: core.DNSClusterFirst, SchedulerName: core.DefaultSchedulerName, EnableServiceLinks: &no, PreemptionPolicy: &preempt,
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Volumes: []core.Volume{
			{Name: "identity", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: &mode, Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: DownloadPeerAudience(p.InstallationID), ExpirationSeconds: &tokenLife, Path: "token"}}}}}},
			{Name: "control", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: p.ControlConfig}, DefaultMode: &mode}}},
		},
		Containers: []core.Container{{Name: "acquisition", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent,
			Command: []string{"/asservat"}, Args: []string{"download-worker", "--installation", p.InstallationID, "--cluster", p.ClusterID, "--dispatch", i.ID, "--session", i.SessionID, "--created-at", i.CreatedAt.UTC().Format(time.RFC3339Nano), "--until", i.RunUntil.UTC().Format(time.RFC3339Nano), "--control-sha256", fmt.Sprintf("%x", p.ControlDigest), "--control", contracts.WorkerControlPath, "--token", DownloadWorkerTokenPath},
			Env:                    []core.EnvVar{{Name: contracts.WorkerPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}},
			TerminationMessagePath: core.TerminationMessagePathDefault, TerminationMessagePolicy: core.TerminationMessageReadFile,
			Resources:       core.ResourceRequirements{Requests: resources, Limits: resources},
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			VolumeMounts:    []core.VolumeMount{{Name: "identity", MountPath: "/run/asservat/identity", ReadOnly: true}, {Name: "control", MountPath: "/run/asservat/control", ReadOnly: true}},
		}},
	}
	for _, name := range p.ImagePullSecrets {
		if name != "" {
			pod.ImagePullSecrets = append(pod.ImagePullSecrets, core.LocalObjectReference{Name: name})
		}
	}
	if p.StoreCredentialSecret != "" {
		pod.Volumes = append(pod.Volumes, core.Volume{Name: "native-store", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: p.StoreCredentialSecret, DefaultMode: &mode, Optional: &no, Items: []core.KeyToPath{{Key: "credentials.json", Path: "credentials.json"}}}}})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, core.VolumeMount{Name: "native-store", MountPath: "/run/asservat/native-store", ReadOnly: true})
	}
	return &batch.Job{TypeMeta: meta.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: meta.ObjectMeta{Name: i.JobName(), Namespace: p.Namespace, Labels: labels}, Spec: batch.JobSpec{Parallelism: &one, Completions: &one, BackoffLimit: &zero, ActiveDeadlineSeconds: &duration, CompletionMode: &completion, PodReplacementPolicy: &replacement, Suspend: &no, ManualSelector: &yes, Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: pod}}}
}
func specBytes(raw []byte) []byte {
	var o struct{ Spec json.RawMessage }
	if json.Unmarshal(raw, &o) != nil {
		return nil
	}
	return o.Spec
}
func (s *DownloadWorkerJobs) checkedJob(i value.DownloadWorkerIntent, raw []byte) (*batch.Job, value.DownloadWorkerJob, error) {
	var j batch.Job
	var receipt value.DownloadWorkerJob
	if permissionJSON(raw, 256<<10, 32768) != nil || json.Unmarshal(raw, &j) != nil || j.APIVersion != "batch/v1" || j.Kind != "Job" || j.Name != i.JobName() || j.Namespace != s.profile.Namespace || !identity.Text(string(j.UID), 64) || j.Labels[workerLabel] != i.ID {
		return nil, receipt, artifact.ErrIntegrity
	}
	expected := workerJob(i)
	if !workerJSONEqual(j.Spec, expected.Spec) {
		return nil, receipt, artifact.ErrIntegrity
	}
	d, e := WorkerSpecDigest("Job", specBytes(raw))
	if e != nil {
		return nil, receipt, e
	}
	b, _ := json.Marshal(j.Spec)
	typed, e := WorkerSpecDigest("Job", b)
	if e != nil || typed != d {
		return nil, receipt, artifact.ErrIntegrity
	}
	return &j, value.DownloadWorkerJob{IntentID: i.ID, UID: string(j.UID), Spec: d}, nil
}
func (s *DownloadWorkerJobs) getJob(ctx context.Context, i value.DownloadWorkerIntent) (*batch.Job, value.DownloadWorkerJob, error) {
	b, e := s.client.api.Get().AbsPath("/apis/batch/v1/namespaces/" + s.profile.Namespace + "/jobs/" + i.JobName()).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		if apierrors.IsNotFound(e) {
			return nil, value.DownloadWorkerJob{}, errWorkerJobMissing
		}
		return nil, value.DownloadWorkerJob{}, artifact.ErrInvalid
	}
	defer clear(b)
	if permissionJSON(b, 256<<10, 32768) != nil {
		return nil, value.DownloadWorkerJob{}, artifact.ErrIntegrity
	}
	return s.checkedJob(i, b)
}
func (s *DownloadWorkerJobs) valid(i value.DownloadWorkerIntent) bool {
	return s != nil && i.Valid() && i.Profile == s.profile && i.RunUntil.Sub(i.CreatedAt) >= time.Second
}
func (s *DownloadWorkerJobs) CreateDownloadWorker(ctx context.Context, l value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	var out value.DownloadWorkerJob
	if ctx == nil || !s.valid(l.Intent) || !l.MayCreate || !l.Valid(s.client.now()) {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, l.Until)
	defer end()
	until, e := s.configuration.CurrentWorkerConfiguration(ctx, l.Intent.Profile)
	if e != nil || !s.client.now().Before(until) {
		return out, artifact.ErrDownloadUnavailable
	}
	ctx, finish := context.WithDeadline(ctx, until)
	defer finish()
	if s.sources(ctx) != nil || !l.Valid(s.client.now()) || ctx.Err() != nil {
		return out, artifact.ErrInvalid
	}
	b, e := json.Marshal(workerJob(l.Intent))
	if e != nil {
		return out, artifact.ErrInvalid
	}
	raw, e := s.client.api.Post().AbsPath("/apis/batch/v1/namespaces/" + s.profile.Namespace + "/jobs").Body(b).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	defer clear(raw)
	_, out, e = s.checkedJob(l.Intent, raw)
	if e != nil || ctx.Err() != nil || !l.Valid(s.client.now()) {
		return value.DownloadWorkerJob{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
func (s *DownloadWorkerJobs) FindDownloadWorkerJob(ctx context.Context, i value.DownloadWorkerIntent) (value.DownloadWorkerJob, error) {
	if ctx == nil || !s.valid(i) {
		return value.DownloadWorkerJob{}, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, r, e := s.getJob(ctx, i)
	return r, e
}
func (s *DownloadWorkerJobs) pods(ctx context.Context, i value.DownloadWorkerIntent) ([]json.RawMessage, error) {
	b, e := s.client.raw(ctx, "/api/v1/namespaces/"+i.Profile.Namespace+"/pods", map[string]string{"labelSelector": workerLabel + "=" + i.ID, "limit": "3"})
	if e != nil {
		return nil, artifact.ErrInvalid
	}
	defer clear(b)
	var list struct {
		APIVersion, Kind string
		Metadata         struct{ ResourceVersion, Continue string }
		Items            []json.RawMessage
	}
	if json.Unmarshal(b, &list) != nil || list.APIVersion != "v1" || list.Kind != "PodList" || list.Metadata.Continue != "" || !identity.Text(list.Metadata.ResourceVersion, 128) || len(list.Items) > 2 {
		return nil, artifact.ErrInvalid
	}
	return list.Items, nil
}
func checkedWorkerPod(i value.DownloadWorkerIntent, j value.DownloadWorkerJob, raw []byte) (*core.Pod, artifact.Digest, error) {
	var p core.Pod
	var zero artifact.Digest
	// The caller obtained this item from a validated v1 PodList at the fixed
	// namespace endpoint. Kubernetes may omit per-item TypeMeta there; if it
	// supplies it, the explicit type must still match. Spec validation is exact.
	if len(raw) > 256<<10 || json.Unmarshal(raw, &p) != nil || (p.APIVersion != "" && p.APIVersion != "v1") || (p.Kind != "" && p.Kind != "Pod") || p.Namespace != i.Profile.Namespace || !value.UUID(string(p.UID)) || p.Labels[workerLabel] != i.ID {
		return nil, zero, artifact.ErrIntegrity
	}
	controllers := 0
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			controllers++
			if o.Kind != "Job" || o.APIVersion != "batch/v1" || o.Name != i.JobName() || string(o.UID) != j.UID {
				return nil, zero, artifact.ErrIntegrity
			}
		}
	}
	if controllers != 1 {
		return nil, zero, artifact.ErrIntegrity
	}
	d, e := WorkerSpecDigest("Pod", specBytes(raw))
	if e != nil {
		return nil, zero, e
	}
	b, _ := json.Marshal(p.Spec)
	typed, e := WorkerSpecDigest("Pod", b)
	if e != nil || typed != d {
		return nil, zero, artifact.ErrIntegrity
	}
	copy := p.Spec.DeepCopy()
	if copy.NodeName != "" && len(validation.IsDNS1123Subdomain(copy.NodeName)) != 0 {
		return nil, zero, artifact.ErrIntegrity
	}
	copy.NodeName = ""
	if copy.Priority != nil {
		if *copy.Priority != 0 {
			return nil, zero, artifact.ErrIntegrity
		}
		copy.Priority = nil
	}
	seen := map[string]bool{}
	for _, v := range copy.Tolerations {
		if (v.Key != "node.kubernetes.io/not-ready" && v.Key != "node.kubernetes.io/unreachable") || seen[v.Key] || v.Operator != core.TolerationOpExists || v.Value != "" || v.Effect != core.TaintEffectNoExecute || v.TolerationSeconds == nil || *v.TolerationSeconds != 300 {
			return nil, zero, artifact.ErrIntegrity
		}
		seen[v.Key] = true
	}
	copy.Tolerations = nil
	if !workerJSONEqual(copy, &workerJob(i).Spec.Template.Spec) {
		return nil, zero, artifact.ErrIntegrity
	}
	return &p, d, nil
}
func workerJobTerminal(j *batch.Job) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batch.JobComplete || c.Type == batch.JobFailed) && c.Status == core.ConditionTrue {
			return true
		}
	}
	return false
}
func (s *DownloadWorkerJobs) ObserveDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, receipt value.DownloadWorkerJob) (value.DownloadWorker, error) {
	var out value.DownloadWorker
	if ctx == nil || !s.valid(i) || !receipt.Valid(i) {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	until, e := s.configuration.CurrentWorkerConfiguration(ctx, i.Profile)
	if e != nil || !start.Before(until) {
		return out, artifact.ErrDownloadUnavailable
	}
	ctx, finish := context.WithDeadline(ctx, until)
	defer finish()
	if !start.Before(i.RunUntil) || s.sources(ctx) != nil {
		return out, artifact.ErrInvalid
	}
	j, r, e := s.getJob(ctx, i)
	if e != nil || r != receipt || j.DeletionTimestamp != nil || workerJobTerminal(j) {
		return out, artifact.ErrDownloadUnavailable
	}
	items, e := s.pods(ctx, i)
	if e != nil || len(items) > 1 {
		return out, artifact.ErrDownloadUnavailable
	}
	pending := func() (value.DownloadWorker, error) {
		if s.client.current(ctx, start, 5*time.Second) != nil {
			return out, artifact.ErrDownloadExpired
		}
		observed := &app.DownloadWorkerPending{Intent: i, Job: receipt, ObservedAt: start, ValidUntil: identity.Earlier(start.Add(5*time.Second), identity.Earlier(until, i.RunUntil))}
		if d, ok := ctx.Deadline(); ok {
			observed.ValidUntil = identity.Earlier(observed.ValidUntil, d)
		}
		if !observed.Valid(s.client.now()) {
			return out, artifact.ErrDownloadExpired
		}
		return out, observed
	}
	if len(items) == 0 {
		if !workerStartupPending(j, nil) {
			return out, artifact.ErrDownloadUnavailable
		}
		return pending()
	}
	p, d, e := checkedWorkerPod(i, receipt, items[0])
	if e != nil || p.DeletionTimestamp != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	if workerStartupPending(j, p) {
		return pending()
	}
	if p.Status.Phase != core.PodRunning || p.Spec.NodeName == "" {
		return out, artifact.ErrDownloadUnavailable
	}
	if s.client.current(ctx, start, 5*time.Second) != nil || !s.client.now().Before(i.RunUntil) {
		return out, artifact.ErrDownloadExpired
	}
	b := value.KeyWorkerBinding{InstallationID: i.Profile.InstallationID, DownloadID: i.SessionID, ClusterID: i.Profile.ClusterID, Namespace: i.Profile.Namespace, NamespaceUID: i.Profile.NamespaceUID, ServiceAccount: i.Profile.ServiceAccount, ServiceAccountUID: i.Profile.ServiceAccountUID, Job: i.JobName(), JobUID: receipt.UID, JobSpec: receipt.Spec, Pod: p.Name, PodUID: string(p.UID), PodSpec: d}
	out = value.DownloadWorker{Intent: i, Job: receipt, Binding: b}
	if !out.Valid() {
		return value.DownloadWorker{}, artifact.ErrIntegrity
	}
	return out, nil
}
func (s *DownloadWorkerJobs) ObserveDownloadWorkerTermination(ctx context.Context, w value.DownloadWorker) (value.DownloadWorkerTermination, error) {
	var out value.DownloadWorkerTermination
	if ctx == nil || !w.Valid() || !s.valid(w.Intent) {
		return out, artifact.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	j, e := s.historicalJob(ctx, w)
	if e != nil || !workerJobTerminal(j) {
		return out, artifact.ErrDownloadUnavailable
	}
	items, e := s.pods(ctx, w.Intent)
	if e != nil || len(items) != 1 {
		return out, artifact.ErrDownloadUnavailable
	}
	selected := false
	h := sha256.New()
	for _, raw := range items {
		p, e := checkedHistoricalPod(w, raw)
		if e != nil || (p.Status.Phase != core.PodSucceeded && p.Status.Phase != core.PodFailed) || len(p.Status.ContainerStatuses) != 1 {
			return out, artifact.ErrDownloadUnavailable
		}
		t := p.Status.ContainerStatuses[0].State.Terminated
		if t == nil || t.FinishedAt.IsZero() || t.FinishedAt.Time.After(s.client.now()) || t.ContainerID == "" || t.Reason == "ContainerStatusUnknown" || t.Reason == "NodeLost" {
			return out, artifact.ErrDownloadUnavailable
		}
		if string(p.UID) == w.Binding.PodUID {
			selected = true
		}
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s", p.UID, t.ContainerID, t.ExitCode, t.FinishedAt.Time.UTC().Format(time.RFC3339Nano))
	}
	if !selected || s.client.current(ctx, start, 5*time.Second) != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	out = value.DownloadWorkerTermination{Worker: w, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	copy(out.TerminationDigest[:], h.Sum(nil))
	return out, nil
}
func (s *DownloadWorkerJobs) RetireDownloadWorker(ctx context.Context, t value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error) {
	var out value.DownloadWorkerRetirement
	if ctx == nil || !t.Valid(t.ObservedAt) || !s.valid(t.Worker.Intent) {
		return out, artifact.ErrInvalid
	}
	i := t.Worker.Intent
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	j, e := s.historicalJob(ctx, t.Worker)
	if e == nil {
		if !workerJobTerminal(j) {
			return out, artifact.ErrDownloadUnavailable
		}
		uid := types.UID(t.Worker.Job.UID)
		foreground := meta.DeletePropagationForeground
		body, _ := json.Marshal(meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid}, PropagationPolicy: &foreground})
		_, e = s.client.api.Delete().AbsPath("/apis/batch/v1/namespaces/" + i.Profile.Namespace + "/jobs/" + i.JobName()).Body(body).MaxRetries(0).DoRaw(ctx)
		if e != nil && !apierrors.IsNotFound(e) {
			return out, artifact.ErrDownloadUnavailable
		}
	} else if e != errWorkerJobMissing {
		return out, e
	}
	if _, e = s.historicalJob(ctx, t.Worker); e != errWorkerJobMissing {
		return out, artifact.ErrDownloadUnavailable
	}
	items, e := s.pods(ctx, i)
	if e != nil || len(items) != 0 || s.client.current(ctx, start, 5*time.Second) != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	return value.DownloadWorkerRetirement{Termination: t, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, nil
}

// Called only after the exact immutable Job and complete bounded Pod list have
// been checked. A failed/completed execution is not a scheduling wait, even if
// its final Job condition has not yet propagated.
func workerStartupPending(j *batch.Job, p *core.Pod) bool {
	if j == nil || j.DeletionTimestamp != nil || workerJobTerminal(j) || j.Status.Failed != 0 || j.Status.Succeeded != 0 || j.Status.CompletionTime != nil || j.Status.Active > 1 {
		return false
	}
	if p == nil {
		return true
	}
	if p.DeletionTimestamp != nil || p.Status.Phase != core.PodPending {
		return false
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.State.Terminated != nil || c.LastTerminationState.Terminated != nil || c.RestartCount != 0 {
			return false
		}
	}
	return true
}
