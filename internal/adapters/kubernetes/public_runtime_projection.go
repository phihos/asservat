package kubernetes

import (
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func clearRuntimeProjection(data map[string][]byte) {
	for _, b := range data {
		clear(b)
	}
}

// The separate capacity projection writer will call this only after its own
// positive projection claim. It includes neither input key nor public roles.
func runtimeCaptureAccountProjection(original contracts.PublicRuntimeRoleSnapshot) ([]byte, error) {
	m := original.State.MAC
	if !authorization.UUID(original.UID) || !authorization.UUID(original.State.OperationID) || m.AccountVersion != original.State.OperationID+"-account/v1" || len(m.AccountKey) != 32 {
		return nil, cfg.ErrUnavailable
	}
	out := contracts.CaptureAccountKey{Format: contracts.CaptureAccountKeyFormat, InstallationID: original.State.Input.InstallationID, RootUID: original.UID, SetupID: original.State.OperationID, Version: m.AccountVersion, Key: m.AccountKey}
	b, e := json.Marshal(out)
	if e != nil || len(b) > contracts.PublicAuditKeysMaxBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}
