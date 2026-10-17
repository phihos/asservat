package kubernetes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Complete public shape preflight. Every SQL role receipt and source interval
// in this fixture is explicitly synthetic, never an installed authority proof.
func configurationWorkerMaterialFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceSnapshot, contracts.ConfigurationRuntimeRoleSnapshot, time.Time) {
	t.Helper()
	s, state := providerResourceFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	// The shared resource-template fixture intentionally omits provider inputs.
	// Supply complete synthetic public endpoints before deriving this new input;
	// no provider is contacted and no native/SQL authority follows from them.
	roots := [][]byte{ownerConfigurationTestRoot(t, now)}
	s.initial.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: "https://api.example.test", Roots: roots}
	s.initial.Postgres = contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1}
	s.initial.AuditStore = contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: roots, Region: "test", Bucket: "audit"}
	s.initial.KeyService = contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: roots, AuditMount: "transit", AuditKey: "configuration-audit"}
	s.initial.FleetGuard.PolicyUID, s.initial.FleetGuard.BindingUID = ownerID(16180), ownerID(16181)
	s.initial.FleetGuard.PolicyGeneration, s.initial.FleetGuard.BindingResourceVersion = 1, "1"
	s.initial.FleetGuard.Administrators = append([]contracts.OwnerDeploymentActor(nil), s.preparer.plan.Administrators...)
	if err := providerconfig.Validate(s.initial.Kubernetes, s.initial.Postgres, s.initial.AuditStore, s.initial.KeyService, now); err != nil {
		t.Fatal("synthetic provider public input preflight", err)
	}
	inventory, err := s.inventory(state)
	if err != nil {
		t.Fatal(err)
	}
	input := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: s.initial.InstallationID,
		InitialClaimID: ownerID(16100), ClusterID: s.initial.ClusterID, Namespace: inventory.Namespace, Deployment: inventory.WorkerDeployment,
		ServiceAccount: inventory.WorkerAccount, FleetSource: inventory.FleetSource, OwnerSource: inventory.OwnerSource, LayoutDigest: strings.Repeat("a", 64)}
	source := contracts.ConfigurationRoleObservation{InstallationID: input.InstallationID, ClusterID: input.ClusterID, IssuerEpoch: s.initial.IssuerEpoch,
		NamespaceUID: input.Namespace.UID, DeploymentUID: input.Deployment.UID, AccountUID: input.ServiceAccount.UID,
		WorkloadDigest: strings.Repeat("b", 64), GuardDigest: strings.Repeat("c", 64), ObservedAt: now, FreshUntil: now.Add(5 * time.Second),
		Fleet: contracts.ConfigurationRoleSourceRevision{UID: input.FleetSource.UID, Generation: 1, Digest: strings.Repeat("d", 64), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)},
		Owner: contracts.ConfigurationRoleSourceRevision{UID: input.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("e", 64), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}
	roles := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: input, OperationID: ownerID(16101), CreatedAt: now, Until: now.Add(30 * time.Minute),
		Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: ownerID(16102), ClaimedAt: now, Until: source.FreshUntil, SecretUID: ownerID(16103)}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		roles.Roles = append(roles.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(key),
			Claim:   &contracts.ConfigurationRuntimeRoleClaim{OperationID: ownerID(16110 + i), ClaimedAt: now, Until: source.FreshUntil, DatabaseOID: 42, PostmasterAt: now.Add(-time.Hour), Sources: source},
			Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: fmt.Sprintf("as_%s_cfg_%02d", strings.ReplaceAll(input.InstallationID, "-", ""), i), RoleOID: uint32(16110 + i), LayoutDigest: input.LayoutDigest}})
	}
	if !s.valid(state) || !configurationRoleStateValid(input, roles, now) {
		t.Fatal("invalid complete synthetic predecessor")
	}
	return s, contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(16104), ResourceVersion: "41", ValidUntil: source.FreshUntil},
		contracts.ConfigurationRuntimeRoleSnapshot{State: roles, UID: ownerID(16105), ResourceVersion: "42", ObservedAt: now, ValidUntil: source.FreshUntil, Sources: source}, now
}

func TestConfigurationWorkerMaterialHasOriginalPublicPredecessorsOnly(t *testing.T) {
	s, resources, roles, now := configurationWorkerMaterialFixture(t)
	before, _ := json.Marshal(resources)
	in, digest, raw, err := s.configurationWorkerInputMaterial(resources, roles, ownerID(16106), now)
	if err != nil {
		t.Fatal("complete predecessor material", err)
	}
	if !HubWorkerActivationBound(in) || digest == "" || in.ProviderInputs == nil || in.ProviderInputs.ConfigurationRoot.UID != roles.UID || in.ProviderInputs.ConfigurationSetupID != roles.State.OperationID ||
		in.ProviderInputs.SQLProjection.UID != roles.State.Projection.SecretUID || in.ProviderAuthentication.AuditCredentials != resources.State.WorkerProvider.AuditCredentials {
		t.Fatal("original provenance lost")
	}
	if bytes.Contains(raw, []byte(digest)) {
		t.Fatal("input adopted its future ConfigMap identity/digest")
	}
	for _, role := range roles.State.Roles {
		if bytes.Contains(raw, []byte(role.Password)) {
			t.Fatal("public document leaked SQL credential")
		}
	}
	if bytes.Contains(raw, []byte(`"client_token"`)) || bytes.Contains(raw, []byte(`"secretAccessKey"`)) {
		t.Fatal("public document acquired provider credentials")
	}
	after, _ := json.Marshal(resources)
	if !bytes.Equal(before, after) {
		t.Fatal("derivation mutated original resource journal")
	}
}

func TestConfigurationWorkerMaterialRejectsIncompleteAndChangedOriginals(t *testing.T) {
	for _, name := range []string{"missing SQL receipt", "missing SQL projection", "foreign worker", "legacy layout", "foreign initial claim cluster", "missing original resource"} {
		t.Run(name, func(t *testing.T) {
			s, resources, roles, now := configurationWorkerMaterialFixture(t)
			switch name {
			case "missing SQL receipt":
				roles.State.Roles[1].Receipt = nil
			case "missing SQL projection":
				roles.State.Projection = nil
			case "foreign worker":
				roles.State.Input.Deployment.UID = ownerID(16190)
			case "legacy layout":
				resources.State.WorkerLayout = contracts.HubWorkerInstalledLayout
			case "foreign initial claim cluster":
				roles.State.Input.ClusterID = ownerID(16190)
			case "missing original resource":
				resources.State.Objects[18].Receipt = nil
			}
			if _, _, _, err := s.configurationWorkerInputMaterial(resources, roles, ownerID(16106), now); err == nil {
				t.Fatal("incomplete predecessor generated usable input")
			}
		})
	}
}
