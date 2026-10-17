// Package configuration owns configuration ingestion ports. Their outputs are
// observed inputs, not current accepted authority. No public CRUD API is added.
package configuration

import (
	value "asservat.local/asservat/internal/domain/configuration"
	"context"
)

type PermissionReader interface {
	PermissionSnapshot(context.Context) (value.Snapshot, error)
}
type NamespaceReader interface {
	NamespaceMetadata(context.Context, value.NamespaceQuery) (value.NamespaceMetadata, error)
}
