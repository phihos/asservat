package live

import "asservat.local/asservat/internal/domain/authorization"

// SourceReference is private routing input, never a permit or public scope.
// C13 supplies authenticated ID/kind; C3 resolves Target independently.
type SourceReference struct {
	ID, Kind string
	Target   authorization.Target
}
