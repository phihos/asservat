package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// This digest binds public generated configuration and original role receipts.
// Neither input can contain passwords, tokens, provider private keys or a hash
// of such material. It is provenance, never current activation authority.
func CaptureCleanupProjectionDigest(deployment CaptureCleanupDeployment, manifest CaptureCleanupCredentialManifest) (string, error) {
	public := struct {
		Format     string
		Deployment CaptureCleanupDeployment
		Manifest   CaptureCleanupCredentialManifest
	}{"asservat-capture-cleanup-projection/v1", deployment, manifest}
	raw, err := json.Marshal(public)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:]), nil
}
