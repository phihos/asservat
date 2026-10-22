package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

var ErrInitialBootstrapRunnerActive = errors.New("original installer runner is not positively terminated")

type InitialBootstrapRunnerResume struct {
	RemovedUID string
	Absent     bool
}

// ResumeInitialBootstrapRunner removes only an exact, positively terminated
// orchestration Pod. It never reads private setup/history/seed or claims that
// SQL/provider recovery completed. An absent runner grants no effect authority.
func ResumeInitialBootstrapRunner(ctx context.Context, c *rest.Config, namespace, name string) (InitialBootstrapRunnerResume, error) {
	var zero InitialBootstrapRunnerResume
	if ctx == nil || ctx.Err() != nil || len(validation.IsDNS1123Label(namespace)) != 0 || len(name) > 30 || len(validation.IsDNS1123Label(name)) != 0 {
		return zero, cfg.ErrInvalid
	}
	api, err := newBoundedAPI(c)
	if err != nil {
		return zero, err
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	path := "/api/v1/namespaces/" + namespace + "/pods/" + name + "-bootstrap"
	raw, err := api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	if apierrors.IsNotFound(err) && ctx.Err() == nil {
		return InitialBootstrapRunnerResume{Absent: true}, nil
	}
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var pod core.Pod
	if strictGuardJSON(raw, &pod) != nil || !preparationDigestValid(pod.Annotations[InitialBootstrapRunnerInputAnnotation]) {
		return zero, cfg.ErrChanged
	}
	originalDigest := pod.Annotations[InitialBootstrapRunnerInputAnnotation]
	inputName := initialBootstrapRunnerInputName(name, originalDigest)
	inputPath := "/api/v1/namespaces/" + namespace + "/configmaps/" + inputName
	raw, err = api.Get().AbsPath(inputPath).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var cm core.ConfigMap
	if strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Namespace != namespace || cm.Name != inputName || !authorization.UUID(string(cm.UID)) || !identity.Text(cm.ResourceVersion, 128) || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 0 || len(cm.BinaryData) != 0 || len(cm.Data) != 2 {
		return zero, cfg.ErrChanged
	}
	input, err := contracts.DecodeInitialBootstrapInput(strings.NewReader(cm.Data["bootstrap.json"]))
	if err != nil || input.Format != contracts.InitialBootstrapInputFormat || input.Name != name || input.BootstrapNamespace != namespace || input.RunnerAccount != name+"-bootstrap-runner" {
		return zero, cfg.ErrChanged
	}
	refs, err := contracts.DecodeInitialBootstrapRunnerInput(strings.NewReader(cm.Data["runner.json"]))
	if err != nil || refs.Format != contracts.InitialBootstrapRunnerInputFormat || (refs.RegistrySecret != "") != (input.RegistryAuthentication == contracts.InitialRegistryAuthentication) || input.RegistryAuthentication != "" && input.RegistryAuthentication != contracts.InitialRegistryAuthentication {
		return zero, cfg.ErrChanged
	}
	sum := sha256.Sum256([]byte(cm.Data["bootstrap.json"] + "\n" + cm.Data["runner.json"]))
	if hex.EncodeToString(sum[:]) != originalDigest {
		return zero, cfg.ErrChanged
	}
	plan := InitialBootstrapRunnerPlan{Namespace: namespace, Name: name, Image: input.Image, InputDigest: hex.EncodeToString(sum[:]), ProducerSecret: refs.ProducerSecret, SchemaSecret: refs.SchemaSecret, RetirementSecret: refs.RetirementSecret, RegistrySecret: refs.RegistrySecret, ProbeAudience: input.ProbeAudience, ContinuationDigest: refs.ContinuationDigest}
	want, err := BuildInitialBootstrapRunner(plan)
	if err != nil {
		return zero, err
	}
	if err = initialBootstrapRunnerTerminal(&pod, want, time.Now()); err != nil {
		return zero, err
	}
	// Recheck original immutable input under the same
	// deadline. Changed/replaced public input cannot authorize this deletion.
	raw, err = api.Get().AbsPath(inputPath).MaxRetries(0).DoRaw(ctx)
	var after core.ConfigMap
	if err != nil || strictGuardJSON(raw, &after) != nil || after.UID != cm.UID || after.ResourceVersion != cm.ResourceVersion || !equalJSON(after.Data, cm.Data) || after.Immutable == nil || !*after.Immutable || after.DeletionTimestamp != nil || ctx.Err() != nil {
		return zero, cfg.ErrChanged
	}
	uid, rv := pod.UID, pod.ResourceVersion
	request, err := json.Marshal(meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	_, err = api.Delete().AbsPath(path).MaxRetries(0).Body(request).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	_, err = api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	if !apierrors.IsNotFound(err) || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	return InitialBootstrapRunnerResume{RemovedUID: string(uid)}, nil
}

func initialBootstrapRunnerTerminal(pod, want *core.Pod, now time.Time) error {
	if pod == nil || want == nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Name != want.Name || pod.Namespace != want.Namespace || !authorization.UUID(string(pod.UID)) || !identity.Text(pod.ResourceVersion, 128) || pod.DeletionTimestamp != nil || len(pod.OwnerReferences) != 0 || len(pod.Finalizers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.EphemeralContainerStatuses) != 0 {
		return cfg.ErrChanged
	}
	for k, v := range want.Annotations {
		if pod.Annotations[k] != v {
			return cfg.ErrChanged
		}
	}
	for k, v := range want.Labels {
		if pod.Labels[k] != v {
			return cfg.ErrChanged
		}
	}
	actual, expected := pod.Spec.DeepCopy(), want.Spec.DeepCopy()
	actual.NodeName = ""
	normalizeInitialPodDefaults(actual)
	normalizeInitialPodDefaults(expected)
	// The same closed Kubernetes defaults apply to every fixed init container.
	for _, s := range []*core.PodSpec{actual, expected} {
		for i := range s.InitContainers {
			if s.InitContainers[i].TerminationMessagePath == core.TerminationMessagePathDefault {
				s.InitContainers[i].TerminationMessagePath = ""
			}
			if s.InitContainers[i].TerminationMessagePolicy == core.TerminationMessageReadFile {
				s.InitContainers[i].TerminationMessagePolicy = ""
			}
		}
	}
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(expected)
	if !bytes.Equal(a, b) {
		return cfg.ErrChanged
	}
	if pod.Status.Phase != core.PodSucceeded && pod.Status.Phase != core.PodFailed || pod.Status.Reason == "NodeLost" || pod.Spec.NodeName == "" {
		return ErrInitialBootstrapRunnerActive
	}
	expectedNames := make([]string, 0, len(want.Spec.InitContainers)+len(want.Spec.Containers))
	initNames, mainNames := map[string]bool{}, map[string]bool{}
	for _, c := range want.Spec.InitContainers {
		expectedNames = append(expectedNames, c.Name)
		initNames[c.Name] = true
	}
	for _, c := range want.Spec.Containers {
		expectedNames = append(expectedNames, c.Name)
		mainNames[c.Name] = true
	}
	statuses := map[string]core.ContainerStatus{}
	for _, s := range pod.Status.InitContainerStatuses {
		if !initNames[s.Name] {
			return cfg.ErrChanged
		}
	}
	for _, s := range pod.Status.ContainerStatuses {
		if !mainNames[s.Name] {
			return cfg.ErrChanged
		}
	}
	for _, s := range append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
		if _, duplicate := statuses[s.Name]; duplicate {
			return cfg.ErrChanged
		}
		statuses[s.Name] = s
	}
	if len(statuses) > len(expectedNames) || len(pod.Status.InitContainerStatuses) > len(initNames) || len(pod.Status.ContainerStatuses) > len(mainNames) {
		return cfg.ErrChanged
	}
	for name := range statuses {
		found := false
		for _, n := range expectedNames {
			found = found || name == n
		}
		if !found {
			return cfg.ErrChanged
		}
	}
	started, unfinished := 0, false
	digest := strings.Split(want.Spec.Containers[0].Image, "@")[1]
	for _, name := range expectedNames {
		s, exists := statuses[name]
		if !exists {
			unfinished = true
			continue
		}
		if s.RestartCount != 0 || s.LastTerminationState.Terminated != nil || s.LastTerminationState.Running != nil || s.LastTerminationState.Waiting != nil || s.State.Running != nil {
			return ErrInitialBootstrapRunnerActive
		}
		terminated := s.State.Terminated
		if terminated == nil {
			// A later init/main which never started needs no invented receipt.
			if s.State.Waiting == nil || s.ContainerID != "" || s.Started != nil && *s.Started {
				return ErrInitialBootstrapRunnerActive
			}
			unfinished = true
			continue
		}
		if unfinished || s.State.Waiting != nil || terminated.ContainerID == "" || s.ContainerID != terminated.ContainerID || terminated.StartedAt.IsZero() || terminated.FinishedAt.IsZero() || terminated.FinishedAt.Before(&terminated.StartedAt) || terminated.FinishedAt.After(now) || !initialBootstrapRunnerImageID(s.ImageID, digest) {
			return ErrInitialBootstrapRunnerActive
		}
		started++
		if terminated.ExitCode != 0 {
			unfinished = true
		}
	}
	if started == 0 || pod.Status.Phase == core.PodSucceeded && (started != len(expectedNames) || unfinished) {
		return ErrInitialBootstrapRunnerActive
	}
	return nil
}

func initialBootstrapRunnerImageID(observed, digest string) bool {
	return observed == digest || observed == "containerd://"+digest || observed == "docker://"+digest || strings.HasSuffix(observed, "@"+digest)
}
