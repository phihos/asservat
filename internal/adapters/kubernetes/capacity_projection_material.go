package kubernetes

import (
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func capacityProjectionMaterial(c contracts.CapacityDeployment, original contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, string, error) {
	v := original.State
	if v.CapacitySetup == nil || v.CapacitySetup.Receipt == nil || c.Format != contracts.CapacityDeploymentFormat ||
		c.InstallationID != v.Input.InstallationID || c.Control.ClusterID != v.Input.ClusterID || c.Control.Namespace != v.Input.Namespace ||
		c.RoleRootUID != original.UID || c.RoleSetupID != v.OperationID || c.PermissionRootID != v.CapacitySetup.PermissionRootID ||
		c.AccountVersion != v.MAC.AccountVersion || c.AccountVersion != v.OperationID+"-account/v1" || len(v.MAC.AccountKey) != 32 ||
		v.CapacitySetup.Receipt.RoleRootUID != original.UID || !capacitySetupStateValid(v, original.ObservedAt) {
		return nil, "", cfg.ErrChanged
	}
	m := contracts.CapacityCredentialManifest{Format: contracts.CapacityCredentialManifestFormat, Input: v.Input, RootUID: original.UID, SetupID: v.OperationID, Capacity: *v.CapacitySetup.Receipt}
	data := make(map[string][]byte, 5)
	ok := false
	defer func() {
		if !ok {
			clearRuntimeProjection(data)
		}
	}()
	for _, purpose := range contracts.CapacityRuntimePurposes() {
		i := slices.IndexFunc(v.Roles, func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if i < 0 || slices.IndexFunc(v.Roles[i+1:], func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose }) >= 0 {
			return nil, "", cfg.ErrChanged
		}
		r := v.Roles[i]
		if r.Claim == nil || r.Receipt == nil || r.Password == "" {
			return nil, "", cfg.ErrChanged
		}
		m.Roles = append(m.Roles, contracts.PublicRuntimeCredentialProof{Purpose: purpose, Claim: *r.Claim, Receipt: *r.Receipt})
		b, e := json.Marshal(contracts.OwnerSQLCredential{Username: r.Receipt.RoleName, Password: r.Password})
		if e != nil {
			return nil, "", cfg.ErrInvalid
		}
		data["sql-"+purpose+".json"] = b
	}
	for _, item := range []struct {
		name  string
		value any
		limit int
	}{
		{contracts.CapacityDeploymentFile, c, contracts.CapacityDeploymentMaxBytes},
		{contracts.CapacityCredentialManifestFile, m, contracts.CapacityCredentialManifestMaxBytes},
		{contracts.CaptureAccountKeyFile, contracts.CaptureAccountKey{Format: contracts.CaptureAccountKeyFormat, InstallationID: c.InstallationID, RootUID: original.UID, SetupID: v.OperationID, Version: v.MAC.AccountVersion, Key: v.MAC.AccountKey}, contracts.PublicAuditKeysMaxBytes},
	} {
		b, e := json.Marshal(item.value)
		if e != nil || len(b) > item.limit {
			clear(b)
			return nil, "", cfg.ErrInvalid
		}
		data[item.name] = b
	}
	ok = true
	return data, CapacityRuntimePublicDigest(c, m), nil
}
