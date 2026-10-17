package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
)

// These are actual responses from one completed native source bracket. They
// have no independent clock, cannot implement a source port and are retained
// only by the existing operation-local proof. The API accepted each configured
// client's credential; SelfSubjectReview itself makes no new audience claim.
type configurationRoleNativeResponses struct {
	clients    [3]*PermissionClient
	identities [3]auth.UserInfo
	worker     core.ServiceAccount
}

// The fresh installed bridge has four explicit probe bindings but only two
// accounts. Reusing one actual object requires every name/UID/client predicate,
// including the processing binding. A matching name or token string is never
// sufficient, and no broader legacy template is inferred from this helper.
func (n *configurationRoleNativeResponses) matches(s *ConfigurationRoleSource, a cfg.InitialRuntimeBridgeAdministration, owner core.ServiceAccount) bool {
	if n == nil || s == nil || s.protection == nil || s.fleet == nil || s.fleet.protection == nil || s.owner == nil || s.owner.protection == nil ||
		n.clients != ([3]*PermissionClient{s.protection.probe, s.fleet.protection.probe, s.owner.protection.probe}) ||
		a.Owner.CapacityProbe == nil || len(a.SourceProbes) != 3 ||
		a.Owner.CapacityProbe.ServiceAccount != s.input.ServiceAccount.Name || a.Owner.CapacityProbe.ServiceAccountUID != s.input.ServiceAccount.UID {
		return false
	}
	ns := s.input.Namespace.Name
	validAccount := func(v core.ServiceAccount, name, uid string) bool {
		return v.APIVersion == "v1" && v.Kind == "ServiceAccount" && ownerMetadata(v.ObjectMeta, ns, name, uid)
	}
	identity := func(v auth.UserInfo, name, uid string) bool {
		if v.Username != "system:serviceaccount:"+ns+":"+name || v.UID != uid {
			return false
		}
		for _, admin := range a.Owner.Administrators {
			if actorMatches(admin, v) {
				return false
			}
		}
		return true
	}
	if !validAccount(n.worker, s.input.ServiceAccount.Name, s.input.ServiceAccount.UID) ||
		!validAccount(owner, a.OwnerProbe.ServiceAccount, a.OwnerProbe.ServiceAccountUID) ||
		!identity(n.identities[0], a.OwnerProbe.ServiceAccount, a.OwnerProbe.ServiceAccountUID) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range a.SourceProbes {
		if seen[p.ConfigMap] || p.ServiceAccount != s.input.ServiceAccount.Name || p.ServiceAccountUID != s.input.ServiceAccount.UID {
			return false
		}
		seen[p.ConfigMap] = true
		native := n.identities[2]
		switch p.ConfigMap {
		case s.input.FleetSource.Name:
			native = n.identities[1]
		case s.input.OwnerSource.Name, installedProcessingSource(s.input.InstallationID):
			// currentProbeAccounts uses this same concrete owner-source client
			// for processing. Neither a fresh token reader nor another client is
			// substituted merely because it names the same service account.
		default:
			return false
		}
		if !identity(native, p.ServiceAccount, p.ServiceAccountUID) {
			return false
		}
	}
	return seen[s.input.FleetSource.Name] && seen[s.input.OwnerSource.Name] && seen[installedProcessingSource(s.input.InstallationID)]
}
