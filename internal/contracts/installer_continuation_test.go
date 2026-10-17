package contracts

import (
	"strings"
	"testing"
)

// ADR-183: the continuation input is closed, so no credential field can be added.
func TestInstallerContinuationIsClosed(t *testing.T) {
	ok := `{"format":"` + InstallerContinuationFormat + `","namespace":"asservat-system","workerProvider":{"authMount":"k","authMountAccessor":"a"},"ownerProvider":{"authMount":"o","authMountAccessor":"b"},"ownerIssuerRootsPEM":"","ownerPKIMount":"owner-pki","ownerConnections":4,"ownerConcurrency":2}`
	if _, err := DecodeInstallerContinuation(strings.NewReader(ok)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstallerContinuation(strings.NewReader(strings.Replace(ok, `"format"`, `"token":"x","format"`, 1))); err == nil {
		t.Fatal("accepted an unknown credential field")
	}
}
