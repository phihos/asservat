package configuration

import (
	"slices"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// InitialRuntimeBridgeAdministration is derived from the acknowledged initial
// plan and actual inert runtime object receipts. It grants no effect itself.
// The two fixed policy candidates are consumed only by the protected installer.
type InitialRuntimeBridgeAdministration struct {
	Initial      InitialWorkloadAdministration
	Owner        OwnerWorkloadAdministration
	Credentials  string
	OwnerProbe   InitialRuntimeProbe
	SourceProbes []InitialRuntimeSourceProbe
}

type InitialRuntimeProbe struct {
	ServiceAccount, ServiceAccountUID string
}

type InitialRuntimeSourceProbe struct {
	ConfigMap, ServiceAccount, ServiceAccountUID string
}

func (p InitialRuntimeBridgeAdministration) Valid() bool {
	if !p.Initial.Valid() || !p.Initial.Handover || !p.Owner.Valid() || p.Initial.ControlNamespace != p.Owner.ControlNamespace || p.Initial.Name == p.Owner.Name || !slices.Equal(p.Initial.Administrators, p.Owner.Administrators) || !identity.Text(p.Credentials, 247) || !identity.Text(p.OwnerProbe.ServiceAccount, 253) || !authorization.UUID(p.OwnerProbe.ServiceAccountUID) || p.OwnerProbe.ServiceAccount == p.Initial.WriterAccount || p.OwnerProbe.ServiceAccount == p.Initial.ProbeAccount || p.OwnerProbe.ServiceAccountUID == p.Initial.WriterAccountUID || p.OwnerProbe.ServiceAccountUID == p.Initial.ProbeAccountUID {
		return false
	}
	// The exact original bootstrap account must remain able to independently
	// observe the old guard. Its namespace/account is never a runtime caller.
	h := p.Owner.InitialHistoryProbe
	if h == nil || h.Configuration != p.Initial.Configuration || h.Namespace == p.Initial.ControlNamespace || h.ServiceAccountUID == p.Initial.WriterAccountUID || h.ServiceAccountUID == p.Initial.ProbeAccountUID || h.ServiceAccountUID == p.OwnerProbe.ServiceAccountUID || len(p.SourceProbes) != p.bridgedProbes() {
		return false
	}
	seen := map[OwnerConfigurationProbe]bool{}
	for _, v := range p.SourceProbes {
		key := OwnerConfigurationProbe{ConfigMap: v.ConfigMap, ServiceAccount: v.ServiceAccount}
		if !authorization.UUID(v.ServiceAccountUID) || seen[key] || !slices.Contains(p.Owner.ConfigurationProbes, key) || v.ConfigMap == p.Initial.Configuration || v.ConfigMap == p.Initial.Witness || v.ServiceAccount == p.Initial.WriterAccount || v.ServiceAccount == p.Initial.ProbeAccount || v.ServiceAccountUID == p.Initial.WriterAccountUID || v.ServiceAccountUID == p.Initial.ProbeAccountUID || v.ServiceAccountUID == h.ServiceAccountUID || v.ServiceAccount == p.OwnerProbe.ServiceAccount {
			return false
		}
		seen[key] = true
	}
	return true
}

// bridgedProbes counts the configuration probes the bridge proves. Probes held
// by the owner probe account belong to the promoted hub-api's own sources
// (ADR-185); those sources do not exist yet at bridge time, and the hub-api
// proves each one at read time.
func (p InitialRuntimeBridgeAdministration) bridgedProbes() int {
	n := 0
	for _, c := range p.Owner.ConfigurationProbes {
		if c.ServiceAccount != p.OwnerProbe.ServiceAccount {
			n++
		}
	}
	return n
}
