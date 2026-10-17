package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// This port owns one protected Kubernetes record, independently of PostgreSQL.
// It cannot create a fresh witness or activate/restore SQL. Bootstrap supplies
// its pinned identities and retires the narrow writer after installation.
type InstallationWitnessReader interface {
	ReadInstallationWitness(context.Context) (value.InstallationWitness, error)
}

type InstallationWitnessConsumer interface {
	ConsumeInstallationWitness(context.Context, value.InitialActivationClaim) (value.InstallationWitness, error)
}
