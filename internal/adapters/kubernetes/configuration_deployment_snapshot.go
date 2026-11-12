package kubernetes

import apps "k8s.io/api/apps/v1"

// A Deployment controller can update status, resourceVersion and managedFields
// without changing the selected workload. Keep every other metadata field and
// the complete spec bound to the original observation. These copies never
// change the actual object's resourceVersion used by the launch write CAS.
func configurationDeploymentSame(a, b apps.Deployment) bool {
	left, right := a.ObjectMeta.DeepCopy(), b.ObjectMeta.DeepCopy()
	left.ResourceVersion, right.ResourceVersion = "", ""
	left.ManagedFields, right.ManagedFields = nil, nil
	return equalJSON(left, right) && equalJSON(a.Spec, b.Spec)
}
