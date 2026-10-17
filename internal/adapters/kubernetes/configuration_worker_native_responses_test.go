package kubernetes

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestConfigurationWorkerNativeResponsesRequireEveryOriginalProbe(t *testing.T) {
	for _, mode := range []string{"valid", "processing-uid", "processing-account", "processing-source", "duplicate-source", "worker-uid", "owner-uid", "owner-identity", "fleet-identity", "processing-identity", "different-client", "missing-capacity", "deleted-worker", "administrator"} {
		t.Run(mode, func(t *testing.T) {
			clients := [3]*PermissionClient{{}, {}, {}}
			s := &ConfigurationRoleSource{protection: &OwnerWorkloadProtection{probe: clients[0]},
				fleet: &ProtectedFleetSettings{protection: &FleetConfigurationProtection{configMapProtection: &configMapProtection{probe: clients[1]}}},
				owner: &OwnerConfigurationSource{protection: &OwnerConfigurationProtection{configMapProtection: &configMapProtection{probe: clients[2]}}},
				input: contracts.ConfigurationRuntimeRoles{InstallationID: ownerID(1), Namespace: contracts.WorkerObjectReference{Name: "owners", UID: ownerID(2)},
					ServiceAccount: contracts.WorkerObjectReference{Name: "worker", UID: ownerID(3)}, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: ownerID(4)}, OwnerSource: contracts.WorkerObjectReference{Name: "owner-source", UID: ownerID(5)}}}
			account := func(name, uid string) core.ServiceAccount {
				return core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "owners", UID: types.UID(uid), ResourceVersion: "1"}}
			}
			who := func(name, uid string) auth.UserInfo {
				return auth.UserInfo{Username: "system:serviceaccount:owners:" + name, UID: uid, Groups: []string{"system:authenticated"}}
			}
			owner := account("owner", ownerID(6))
			p := cfg.InitialRuntimeBridgeAdministration{Owner: cfg.OwnerWorkloadAdministration{CapacityProbe: &cfg.OwnerCapacityProbe{ServiceAccount: "worker", ServiceAccountUID: ownerID(3)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}},
				OwnerProbe:   cfg.InitialRuntimeProbe{ServiceAccount: "owner", ServiceAccountUID: ownerID(6)},
				SourceProbes: []cfg.InitialRuntimeSourceProbe{{ConfigMap: "fleet", ServiceAccount: "worker", ServiceAccountUID: ownerID(3)}, {ConfigMap: "owner-source", ServiceAccount: "worker", ServiceAccountUID: ownerID(3)}, {ConfigMap: installedProcessingSource(ownerID(1)), ServiceAccount: "worker", ServiceAccountUID: ownerID(3)}}}
			n := configurationRoleNativeResponses{clients: clients, identities: [3]auth.UserInfo{who("owner", ownerID(6)), who("worker", ownerID(3)), who("worker", ownerID(3))}, worker: account("worker", ownerID(3))}
			switch mode {
			case "processing-uid":
				p.SourceProbes[2].ServiceAccountUID = ownerID(99)
			case "processing-account":
				p.SourceProbes[2].ServiceAccount = "other"
			case "processing-source":
				p.SourceProbes[2].ConfigMap = "other"
			case "duplicate-source":
				p.SourceProbes[2].ConfigMap = "fleet"
			case "worker-uid":
				n.worker.UID = types.UID(ownerID(99))
			case "owner-uid":
				owner.UID = types.UID(ownerID(99))
			case "owner-identity":
				n.identities[0].UID = ownerID(99)
			case "fleet-identity":
				n.identities[1].UID = ownerID(99)
			case "processing-identity":
				n.identities[2].UID = ownerID(99)
			case "different-client":
				n.clients[2] = &PermissionClient{}
			case "missing-capacity":
				p.Owner.CapacityProbe = nil
			case "deleted-worker":
				n.worker.DeletionTimestamp = &meta.Time{}
			case "administrator":
				p.Owner.Administrators = append(p.Owner.Administrators, cfg.KubernetesActor{Kind: "Group", Name: "system:authenticated"})
			}
			if got := n.matches(s, p, owner); got != (mode == "valid") {
				t.Fatalf("four original probe bindings: accepted=%t", got)
			}
		})
	}
}
