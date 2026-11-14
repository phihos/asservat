package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
)

type configurationProviderProcess struct {
	ReplicaSetUID string
	Template      artifact.Digest
}
