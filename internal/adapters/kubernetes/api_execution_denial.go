package kubernetes

import (
	"errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func exactAPIExecutionDenial(err error, raw []byte, name string) bool {
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || (!apierrors.IsForbidden(err) && !apierrors.IsInvalid(err)) {
		return false
	}
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	d := status.Status()
	if d.Details == nil || d.Details.Kind != "pods" || d.Details.Group != "" || len(d.Details.Causes) > 8 {
		return false
	}
	expected := "ValidatingAdmissionPolicy '" + name + "' with binding '" + name + "' denied request: " + apiExecutionDenial
	for _, cause := range d.Details.Causes {
		if cause.Message == expected {
			return true
		}
	}
	return false
}

// A status update may advance resourceVersion after the GET. Retry only this
// exact object's native conflict, within the original guard observation interval.
func exactAPIExecutionConflict(err error, raw []byte, name, uid string) bool {
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || !apierrors.IsConflict(err) {
		return false
	}
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	d := status.Status()
	return d.Code == 409 && d.Reason == meta.StatusReasonConflict && d.Status == meta.StatusFailure && d.Details != nil && d.Details.Group == "" && d.Details.Kind == "pods" && d.Details.Name == name && (d.Details.UID == "" || string(d.Details.UID) == uid) && len(d.Details.Causes) == 0
}
