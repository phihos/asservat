package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ReleaseRecordRevision is a read record with the resourceVersion that the
// next compare-and-swap update requires.
type ReleaseRecordRevision struct {
	Record          contracts.ReleaseRecord
	ResourceVersion string
}

// HubDeploymentNames returns the hub-api and hub-worker Deployment names.
func HubDeploymentNames(installation string) (hubAPI, hubWorker string) {
	n := runtimeResourceNames(installation)
	return n.Owner, n.Worker
}

// HubDeploymentNamesList is HubDeploymentNames as a list.
func HubDeploymentNamesList(installation string) []string {
	a, w := HubDeploymentNames(installation)
	return []string{a, w}
}

// ReadReleaseRecord reads the record as the installer runner. An absent
// record is cfg.ErrUnavailable: an upgrade requires a phase-2 installation.
func ReadReleaseRecord(ctx context.Context, config *rest.Config, namespace, installation string) (ReleaseRecordRevision, error) {
	if ctx == nil || config == nil || !authorization.UUID(installation) || namespace == "" {
		return ReleaseRecordRevision{}, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return ReleaseRecordRevision{}, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/" + namespace + "/configmaps/" + contracts.ReleaseRecordName(installation)).MaxRetries(0).DoRaw(call)
	if err != nil {
		return ReleaseRecordRevision{}, cfg.ErrUnavailable
	}
	r, rv, err := decodeReleaseConfigMap(raw, namespace, installation)
	if err != nil {
		return ReleaseRecordRevision{}, err
	}
	return ReleaseRecordRevision{*r, rv}, nil
}

func releaseConfigMap(namespace string, r contracts.ReleaseRecord, rv string) (*core.ConfigMap, error) {
	body, err := contracts.EncodeReleaseRecord(r)
	if err != nil {
		return nil, err
	}
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: contracts.ReleaseRecordName(r.InstallationID), Namespace: namespace, ResourceVersion: rv}, Data: map[string]string{contracts.ReleaseRecordFile: string(body)}}, nil
}

// CreateReleaseRecord creates revision 1 once. A replay finds the existing
// record and accepts it only when it is exactly this revision 1, or a later
// revision of the same installation and original image (a continuation
// replayed after an upgrade).
func CreateReleaseRecord(ctx context.Context, config *rest.Config, namespace string, r contracts.ReleaseRecord) error {
	if ctx == nil || config == nil || namespace == "" || r.Validate() != nil || r.Revision != 1 {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	object, err := releaseConfigMap(namespace, r, "")
	if err != nil {
		return err
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err = api.CoreV1().ConfigMaps(namespace).Create(call, object, meta.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return cfg.ErrUnavailable
	}
	current, err := ReadReleaseRecord(call, config, namespace, r.InstallationID)
	if err != nil {
		return err
	}
	c := current.Record
	if c.Revision == 1 && !equalJSON(c, r) || c.Original != r.Original || c.InstallationID != r.InstallationID {
		return cfg.ErrChanged
	}
	return nil
}

// UpdateReleaseRecord replaces the record only at the read resourceVersion
// (UPDATE, never PATCH) and returns the new resourceVersion.
func UpdateReleaseRecord(ctx context.Context, config *rest.Config, namespace string, r contracts.ReleaseRecord, rv string) (string, error) {
	if ctx == nil || config == nil || namespace == "" || rv == "" || r.Validate() != nil {
		return "", cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return "", cfg.ErrInvalid
	}
	object, err := releaseConfigMap(namespace, r, rv)
	if err != nil {
		return "", err
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	out, err := api.CoreV1().ConfigMaps(namespace).Update(call, object, meta.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return "", cfg.ErrChanged
	}
	if err != nil || out.ResourceVersion == "" {
		return "", cfg.ErrUnavailable
	}
	return out.ResourceVersion, nil
}

// ReleaseFollowerNames are the hub-namespace Deployments that follow the
// release image without any runtime check of their own image (ADR-227 phase
// 3): the key service, publisher and federation, in rollout order. Each exists
// only when the installation enabled it.
func ReleaseFollowerNames(installation string) []string {
	return []string{contracts.KeyServiceName(installation), contracts.PublisherName(installation), FederationWorkloadName(installation)}
}

// ReadHubDeployment reads one hub Deployment as the installer runner.
func ReadHubDeployment(ctx context.Context, config *rest.Config, namespace, name string) (apps.Deployment, error) {
	d, found, err := ReadOptionalHubDeployment(ctx, config, namespace, name)
	if err == nil && !found {
		return apps.Deployment{}, cfg.ErrUnavailable
	}
	return d, err
}

// ReadOptionalHubDeployment is ReadHubDeployment that reports an absent
// Deployment as not found instead of an error.
func ReadOptionalHubDeployment(ctx context.Context, config *rest.Config, namespace, name string) (apps.Deployment, bool, error) {
	if ctx == nil || config == nil || namespace == "" || name == "" {
		return apps.Deployment{}, false, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return apps.Deployment{}, false, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/apis/apps/v1/namespaces/" + namespace + "/deployments/" + name).MaxRetries(0).DoRaw(call)
	if apierrors.IsNotFound(err) {
		return apps.Deployment{}, false, nil
	}
	if err != nil {
		return apps.Deployment{}, false, cfg.ErrUnavailable
	}
	var d apps.Deployment
	if json.Unmarshal(raw, &d) != nil || d.APIVersion != "apps/v1" || d.Kind != "Deployment" || d.Name != name || d.Namespace != namespace || len(d.Spec.Template.Spec.Containers) != 1 {
		return apps.Deployment{}, false, cfg.ErrChanged
	}
	return d, true, nil
}

// ReleaseDeploymentMatches reports whether a hub Deployment runs an image the
// record names at the matching generation (ADR-227's releaseOriginal rule).
func ReleaseDeploymentMatches(d apps.Deployment, r contracts.ReleaseRecord, hubAPI bool) bool {
	w := releaseHubWorker
	if hubAPI {
		w = releaseHubAPI
	}
	if r.Revision == 1 {
		return d.Spec.Template.Spec.Containers[0].Image == r.Original
	}
	_, err := releaseOriginal(d, &r, w)
	return err == nil
}

// UpdateHubDeploymentImage changes only the container image of the read
// Deployment, at its resourceVersion, and returns the new generation.
func UpdateHubDeploymentImage(ctx context.Context, config *rest.Config, d apps.Deployment, image string) (int64, error) {
	if ctx == nil || config == nil || !contracts.ReleaseImageValid(image) || len(d.Spec.Template.Spec.Containers) != 1 || d.ResourceVersion == "" {
		return 0, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return 0, cfg.ErrInvalid
	}
	next := d.DeepCopy()
	next.Spec.Template.Spec.Containers[0].Image = image
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	out, err := api.AppsV1().Deployments(d.Namespace).Update(call, next, meta.UpdateOptions{FieldValidation: "Strict"})
	if apierrors.IsConflict(err) {
		return 0, cfg.ErrChanged
	}
	if err != nil {
		return 0, cfg.ErrUnavailable
	}
	return out.Generation, nil
}

// VerifyOwnPodImage requires that the named Pod (the running installer-upgrade
// Pod) runs exactly one container, of image.
func VerifyOwnPodImage(ctx context.Context, config *rest.Config, namespace, name, image string) error {
	if ctx == nil || config == nil || namespace == "" || name == "" || !contracts.ReleaseImageValid(image) {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	pod, err := api.CoreV1().Pods(namespace).Get(call, name, meta.GetOptions{})
	if err != nil {
		return cfg.ErrUnavailable
	}
	if len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || pod.Spec.Containers[0].Image != image || pod.Status.Phase != core.PodRunning {
		return cfg.ErrChanged
	}
	return nil
}

// HubDeploymentSettled reports whether the Deployment's controller has
// observed its current generation and runs exactly one updated, available
// replica with no other ReplicaSet holding replicas.
func HubDeploymentSettled(d apps.Deployment) bool {
	s := d.Status
	return d.Spec.Replicas != nil && *d.Spec.Replicas == 1 && s.ObservedGeneration == d.Generation && s.Replicas == 1 && s.UpdatedReplicas == 1 && s.AvailableReplicas == 1 && s.ReadyReplicas == 1 && s.UnavailableReplicas == 0
}
