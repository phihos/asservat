package providerconfig

import (
	"crypto/rand"
	"encoding/hex"

	"asservat.local/asservat/internal/contracts"
)

// GenerateSeaweedStorageCredential creates private credential bytes only. It
// grants no provider permission and carries no purpose or installation identity.
// Initial installation persists these bytes in its original material before
// binding a typed principal to the independently stored installation ID.
func GenerateSeaweedStorageCredential() (contracts.OwnerStorageCredential, error) {
	var access [20]byte
	var secret [32]byte
	defer clear(access[:])
	defer clear(secret[:])
	if _, err := rand.Read(access[:]); err != nil {
		return contracts.OwnerStorageCredential{}, ErrSeaweedStorage
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return contracts.OwnerStorageCredential{}, ErrSeaweedStorage
	}
	return contracts.OwnerStorageCredential{AccessKeyID: "ASV" + hex.EncodeToString(access[:]), SecretAccessKey: hex.EncodeToString(secret[:])}, nil
}
