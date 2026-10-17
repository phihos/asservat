package kubernetes

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func configurationProjectedEpochFixture() (contracts.HubWorkerDeployment, contracts.ConfigurationRuntimeCredentialManifest) {
	in := contracts.HubWorkerDeployment{InstallationID: ownerID(701), ClusterID: ownerID(702),
		Namespace:   contracts.WorkerObjectReference{Name: "runtime", UID: ownerID(703)},
		FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: ownerID(704)}, OwnerSource: contracts.WorkerObjectReference{Name: "owner", UID: ownerID(705)},
		Activation:     &contracts.HubWorkerRuntimeActivation{Deployment: contracts.WorkerObjectReference{Name: "worker", UID: ownerID(706)}, ServiceAccount: contracts.WorkerObjectReference{Name: "worker", UID: ownerID(707)}},
		ProviderInputs: &contracts.ConfigurationWorkerInputProvenance{ConfigurationRoot: contracts.WorkerObjectReference{Name: "configuration", UID: ownerID(708)}, ConfigurationSetupID: ownerID(709)}}
	m := contracts.ConfigurationRuntimeCredentialManifest{Format: contracts.ConfigurationRuntimeCredentialManifestFormat, RootUID: in.ProviderInputs.ConfigurationRoot.UID, SetupID: in.ProviderInputs.ConfigurationSetupID,
		Input: contracts.ConfigurationRuntimeRoles{InstallationID: in.InstallationID, ClusterID: in.ClusterID, Namespace: in.Namespace, Deployment: in.Activation.Deployment, ServiceAccount: in.Activation.ServiceAccount, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource}}
	for _, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		m.Roles = append(m.Roles, contracts.ConfigurationRuntimeCredentialProof{Purpose: purpose, Claim: contracts.ConfigurationRuntimeRoleClaim{Sources: contracts.ConfigurationRoleObservation{
			InstallationID: in.InstallationID, ClusterID: in.ClusterID, NamespaceUID: in.Namespace.UID, DeploymentUID: in.Activation.Deployment.UID, AccountUID: in.Activation.ServiceAccount.UID,
			IssuerEpoch: ownerID(710), Fleet: contracts.ConfigurationRoleSourceRevision{UID: in.FleetSource.UID}, Owner: contracts.ConfigurationRoleSourceRevision{UID: in.OwnerSource.UID},
		}}})
	}
	return in, m
}

func TestConfigurationProjectedEpochIsOnlyOriginalComparisonPin(t *testing.T) {
	in, m := configurationProjectedEpochFixture()
	// A historical receipt need not pretend it is a current observation. This
	// pure result never opens SQL or provides RecoveryState; VerifyProjected must
	// still obtain all actual native proofs, and effects require current SQL.
	for i := range m.Roles {
		m.Roles[i].Claim.Sources.FreshUntil = time.Unix(1, 0)
	}
	if epoch, err := configurationProjectedEpoch(in, m); err != nil || epoch != ownerID(710) {
		t.Fatalf("original pin: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*contracts.ConfigurationRuntimeCredentialManifest)
	}{
		{"different epoch", func(v *contracts.ConfigurationRuntimeCredentialManifest) {
			v.Roles[1].Claim.Sources.IssuerEpoch = ownerID(711)
		}},
		{"invalid epoch", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.Roles[2].Claim.Sources.IssuerEpoch = "" }},
		{"missing purpose", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.Roles = v.Roles[:2] }},
		{"duplicate purpose", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.Roles[2].Purpose = v.Roles[0].Purpose }},
		{"foreign account", func(v *contracts.ConfigurationRuntimeCredentialManifest) {
			v.Roles[1].Claim.Sources.AccountUID = ownerID(711)
		}},
		{"foreign source", func(v *contracts.ConfigurationRuntimeCredentialManifest) {
			v.Roles[1].Claim.Sources.Owner.UID = ownerID(711)
		}},
		{"foreign root", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.RootUID = ownerID(711) }},
		{"foreign setup", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.SetupID = ownerID(711) }},
		{"foreign worker", func(v *contracts.ConfigurationRuntimeCredentialManifest) { v.Input.Deployment.UID = ownerID(711) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var changed contracts.ConfigurationRuntimeCredentialManifest
			b, err := json.Marshal(m)
			if err != nil || json.Unmarshal(b, &changed) != nil {
				t.Fatal("fixture copy")
			}
			tc.mutate(&changed)
			if _, err := configurationProjectedEpoch(in, changed); err == nil {
				t.Fatal("accepted mismatched original comparison pins")
			}
		})
	}
}
