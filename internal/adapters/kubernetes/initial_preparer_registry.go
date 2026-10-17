package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

func (s *InitialPreparer) providerProjectionType() core.SecretType {
	if s.plan.Workload.RegistryAuthentication == contracts.InitialRegistryAuthentication {
		return core.SecretTypeDockerConfigJson
	}
	return core.SecretTypeOpaque
}

// The extra Secret key is for kubelet only. The activation volume's seven
// explicit items remain unchanged. The same original create/UID/closed request
// and positive handover cleanup cover this combined immutable Secret.
func (s *InitialPreparer) providerProjectionData(files map[string][]byte, registry []byte) (core.SecretType, error) {
	w := s.plan.Workload
	if len(files) != 7 || !providerconfig.InitialRegistryMaterial(w.Image, w.RegistryAuthentication, registry) {
		return "", cfg.ErrInvalid
	}
	for _, name := range []string{"sql-prepare.json", "sql-audit.json", "sql-activate.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "kube-probe.token"} {
		if len(files[name]) == 0 {
			return "", cfg.ErrInvalid
		}
	}
	total := len(registry)
	for _, data := range files {
		total += len(data)
	}
	if total > core.MaxSecretSize {
		return "", cfg.ErrInvalid
	}
	if w.RegistryAuthentication == contracts.InitialRegistryAuthentication {
		files[core.DockerConfigJsonKey] = append([]byte(nil), registry...)
	}
	return s.providerProjectionType(), nil
}
