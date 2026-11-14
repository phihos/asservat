package kubernetes

import (
	"net/http"
	"strings"

	apps "k8s.io/api/apps/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// releaseRecordAbsent answers a fixture API server's release record read with
// NotFound (no record: only the original image verifies).
func releaseRecordAbsent(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/configmaps/asservat-release-") {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: 404})
	return true
}

func releaseDeployment(image string, generation int64, revision string) apps.Deployment {
	d, _, _, _ := connectorAPITemplateFixture()
	d.Generation = generation
	d.Annotations = map[string]string{"asservat.io/marker": "x"}
	if revision != "" {
		d.Annotations[deploymentRevisionAnnotation] = revision
	}
	d.Spec.Template.Spec.Containers[0].Image = image
	return d
}
