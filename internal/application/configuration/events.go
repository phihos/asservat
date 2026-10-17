package configuration

import (
	value "asservat.local/asservat/internal/domain/configuration"
	"context"
)

// A watch is resumed only from its last processed opaque cursor. Expired history
// requires a new baseline; a relist cannot assert continuous ownership history.
// io.EOF is a clean finite stream end; reconnect from the last committed cursor.
type BindingWatch interface {
	Next(context.Context) (value.BindingEvent, error)
	Close()
}
type BindingWatcher interface {
	WatchBindings(context.Context, string) (BindingWatch, error)
}
