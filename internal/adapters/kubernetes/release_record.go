package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// releaseWorkload selects one hub Deployment's generations in the record.
type releaseWorkload int

const (
	releaseHubAPI releaseWorkload = iota + 1
	releaseHubWorker
)

func (w releaseWorkload) of(r *contracts.ReleaseRecord) (contracts.ReleaseWorkload, bool) {
	switch w {
	case releaseHubAPI:
		return r.Workloads.HubAPI, true
	case releaseHubWorker:
		return r.Workloads.HubWorker, true
	}
	return contracts.ReleaseWorkload{}, false
}

const deploymentRevisionAnnotation = "deployment.kubernetes.io/revision"

// decodeReleaseConfigMap accepts only the exact record ConfigMap: its fixed
// name in the hub namespace, one state.json key and no labels, annotations,
// owners, finalizers or binary data.
func decodeReleaseConfigMap(raw []byte, namespace, installation string) (*contracts.ReleaseRecord, string, error) {
	var m core.ConfigMap
	if json.Unmarshal(raw, &m) != nil || m.APIVersion != "v1" || m.Kind != "ConfigMap" || m.Name != contracts.ReleaseRecordName(installation) || m.Namespace != namespace ||
		m.UID == "" || m.ResourceVersion == "" || m.DeletionTimestamp != nil || len(m.Labels) != 0 || len(m.Annotations) != 0 || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 ||
		len(m.BinaryData) != 0 || len(m.Data) != 1 || (m.Immutable != nil && *m.Immutable) {
		return nil, "", cfg.ErrChanged
	}
	data, ok := m.Data[contracts.ReleaseRecordFile]
	if !ok {
		return nil, "", cfg.ErrChanged
	}
	r, err := contracts.DecodeReleaseRecord(bytes.NewBufferString(data))
	if err != nil || r.InstallationID != installation {
		return nil, "", cfg.ErrChanged
	}
	return &r, m.ResourceVersion, nil
}

// releaseRecord reads the installation's release record with this client. An
// absent record (an installation before ADR-227 phase 2, or before the
// continuation created it) is nil: only the original image then verifies.
// Any other failure, including a denied read, is an error.
func (c *PermissionClient) releaseRecord(ctx context.Context, namespace, installation string) (*contracts.ReleaseRecord, error) {
	if c == nil || ctx == nil || !authorization.UUID(installation) || namespace == "" {
		return nil, cfg.ErrInvalid
	}
	raw, err := c.api.Get().AbsPath("/api/v1/namespaces/" + namespace + "/configmaps/" + contracts.ReleaseRecordName(installation)).MaxRetries(0).DoRaw(ctx)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, permissionError(ctx, err)
	}
	if err = permissionJSON(raw, permissionPageBytes, 131072); err != nil {
		return nil, err
	}
	r, _, err := decodeReleaseConfigMap(raw, namespace, installation)
	return r, err
}

// releaseOriginalImage maps an image the record names (current or previous)
// to the original revision-1 image. Without a record, or at revision 1, the
// image is returned unchanged; any other image maps to "", which no check
// accepts.
func releaseOriginalImage(image string, r *contracts.ReleaseRecord) string {
	if r == nil || r.Revision == 1 {
		return image
	}
	if image == r.Image || (r.Previous != "" && image == r.Previous) {
		return r.Original
	}
	return ""
}

// releaseOriginal is ADR-227's single mapping for a hub Deployment: the live
// image must be the record's current image at that workload's generation or
// its previous image at the previous generation. It returns a copy with the
// original image, the launch generation and, when present, the revision
// annotation "1", so every existing install-time check runs unchanged on it.
// Without a record or at revision 1 the Deployment is returned unchanged.
func releaseOriginal(d apps.Deployment, r *contracts.ReleaseRecord, w releaseWorkload) (apps.Deployment, error) {
	out := *d.DeepCopy()
	if r == nil || r.Revision == 1 {
		return out, nil
	}
	g, ok := w.of(r)
	if !ok || len(out.Spec.Template.Spec.Containers) != 1 {
		return apps.Deployment{}, cfg.ErrChanged
	}
	image := out.Spec.Template.Spec.Containers[0].Image
	switch {
	case image == r.Image && d.Generation == g.Generation:
	case r.Previous != "" && image == r.Previous && d.Generation == g.PreviousGeneration:
	default:
		return apps.Deployment{}, cfg.ErrChanged
	}
	if v, ok := out.Annotations[deploymentRevisionAnnotation]; ok {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 || strconv.FormatUint(n, 10) != v {
			return apps.Deployment{}, cfg.ErrChanged
		}
		out.Annotations[deploymentRevisionAnnotation] = "1"
	}
	out.Spec.Template.Spec.Containers[0].Image = r.Original
	out.Generation = g.Launch
	return out, nil
}

// releaseOriginalReplicaSet and releaseOriginalPod map the template and Pod
// images the same way; every other field stays as observed.
func releaseOriginalReplicaSet(rs apps.ReplicaSet, r *contracts.ReleaseRecord) apps.ReplicaSet {
	out := *rs.DeepCopy()
	for i := range out.Spec.Template.Spec.Containers {
		out.Spec.Template.Spec.Containers[i].Image = releaseOriginalImage(out.Spec.Template.Spec.Containers[i].Image, r)
	}
	return out
}

func releaseOriginalPod(p core.Pod, r *contracts.ReleaseRecord) core.Pod {
	out := *p.DeepCopy()
	for i := range out.Spec.Containers {
		out.Spec.Containers[i].Image = releaseOriginalImage(out.Spec.Containers[i].Image, r)
	}
	return out
}
