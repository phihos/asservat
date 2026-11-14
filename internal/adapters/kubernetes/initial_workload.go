package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type InitialWorkloadProtection struct {
	guard *configMapProtection
	plan  cfg.InitialWorkloadAdministration
}
