package execution

import (
	"context"

	value "asservat.local/asservat/internal/domain/execution"
)

// StartJournal consumes an existing exact prepaid start. Missing state is not
// recreated here. An uncertain write requires lookup and never a new effect.
type StartJournal interface {
	ConsumeStart(context.Context, value.Request) (value.Disposition, error)
	LookupStart(context.Context, value.Request) (value.Disposition, error)
}
