package objectstore

import (
	"asservat.local/asservat/internal/application/evidence"
)

// Bootstrap-only key/store credentials are supplied by protected installation,
// not an ordinary evidence authority that would depend on already-active SQL.
type InitialInstallationObjects struct {
	Store *Store
	Seal  evidence.KeySealer
	Open  evidence.KeyOpener
}
