package postgres

import (
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// InitialSchemaIncarnation validates immutable compiled provenance only. It
// supplies no current database observation or permission to create a claim.
func InitialSchemaIncarnation(v contracts.InitialSchemaExpectation) (value.DatabaseIncarnation, error) {
	b, err := EmbeddedInitialSchema()
	db := value.DatabaseIncarnation{StartedAt: v.PostmasterAt, DatabaseOID: v.DatabaseOID, SchemaVersion: v.Head}
	if err != nil || v.BundleDigest != b.Digest || v.Head != b.Head || !db.Valid() || !v.PostmasterAt.Equal(ownerTime(v.PostmasterAt)) {
		return value.DatabaseIncarnation{}, value.ErrInvalid
	}
	return db, nil
}
