package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type AdministrationReader interface {
	FleetAdministration(context.Context) (value.Administration, error)
}
