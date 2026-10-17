package kubernetes

import (
	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
)

const workerConfigurationDenial = "Asservat worker configuration administrator is required."

type WorkerConfigurationProtection struct{ *configMapProtection }

func WorkerConfigurationAdmission(p value.WorkerAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-worker-namespace", workerConfigurationDenial)
}
func NewWorkerConfigurationProtection(observer, probe *PermissionClient, plan value.WorkerAdministration, pin GuardPin) (*WorkerConfigurationProtection, error) {
	g, err := newConfigMapProtection(observer, probe, plan, pin, "protected-worker-namespace", workerConfigurationDenial)
	if err != nil {
		return nil, err
	}
	return &WorkerConfigurationProtection{g}, nil
}
