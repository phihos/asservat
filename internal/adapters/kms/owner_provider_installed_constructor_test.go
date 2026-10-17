package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/client-go/rest"
)

type installedConstructorUnusedToken struct{ t *testing.T }

func (s installedConstructorUnusedToken) ReadOwnerPodToken(context.Context) ([]byte, error) {
	s.t.Error("constructor attempted current authority or credential effects")
	return nil, ErrKeyService
}

// Constructor input ownership only. The empty SQL adapter and unserved native
// client provide no usable authority; Run/Prime/effects are deliberately absent.
func TestInstalledOwnerProviderConstructorRetainsOriginalInput(t *testing.T) {
	in, account, secret, now := ownerProviderRecipeInput(t)
	id := func(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
	suffix := strings.ReplaceAll(in.InstallationID, "-", "")
	ownerName := "asservat-" + suffix + "-owner"
	account.Name = ownerName
	secret.Name = contracts.OwnerProviderAuditSecretName(in.InstallationID)
	in.ConfigurationUID, in.Concurrency = id(7), 2
	in.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: "original-guard", PolicyUID: id(10), PolicyGeneration: 1, BindingUID: id(11), BindingResourceVersion: "1"}
	a := contracts.OwnerIdentityActivation{Input: contracts.OwnerIdentityRoles{Format: contracts.OwnerIdentityRolesFormat, InstallationID: in.InstallationID, InitialClaimID: id(6), ClusterID: in.ClusterID, Namespace: in.Namespace, OwnerConfigurationUID: in.ConfigurationUID, Resources: contracts.WorkerObjectReference{Name: "asservat-runtime-resources-" + suffix, UID: id(12)}, ResourceSetupID: id(13), ResourceBinding: strings.Repeat("1", 64), OwnerLayout: contracts.OwnerProviderInstalledLayout, Deployment: contracts.WorkerObjectReference{Name: ownerName, UID: id(14)}, ServiceAccount: account, LayoutDigest: strings.Repeat("2", 64)}, RoleRoot: contracts.WorkerObjectReference{Name: "asservat-owner-identity-roles-" + suffix, UID: id(15)}, RoleSetupID: id(16), ResourcesCreatedAt: now.Add(-time.Second).Truncate(time.Microsecond)}
	a.ResourcesUntil = a.ResourcesCreatedAt.Add(30 * time.Minute)
	in.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, Activation: &a, TemplateDigest: strings.Repeat("3", 64), ImageDigest: strings.Repeat("4", 64), ProtectionDigest: strings.Repeat("5", 64)}
	recipe, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_original", account, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = &recipe.Profile
	namespace := cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}
	client, err := kubernetes.NewPermissionClient(&rest.Config{Host: in.Kubernetes.Endpoint}, in.ClusterID, namespace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	probe := *client
	plan := cfg.OwnerWorkloadAdministration{Name: in.WorkloadGuard.Name, ControlNamespace: namespace, Deployment: ownerName, DeploymentUID: a.Input.Deployment.UID, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "synthetic-installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "original-owner-source", ServiceAccount: "source-probe"}}}
	protection, err := kubernetes.NewOwnerWorkloadProtection(client, &probe, plan, kubernetes.GuardPin{PolicyUID: in.WorkloadGuard.PolicyUID, PolicyGeneration: 1, BindingUID: in.WorkloadGuard.BindingUID, BindingResourceVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kubernetes.NewInstalledOwnerIdentityReader(client, protection, in, a, installedConstructorUnusedToken{t}, id(17))
	if err != nil {
		t.Fatal(err)
	}
	pool := fleet.OwnerPool{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: id(18), Namespace: in.Namespace.Name, NamespaceUID: in.Namespace.UID, Service: "owner", ServiceUID: id(19), Deployment: ownerName, DeploymentUID: a.Input.Deployment.UID, ServiceAccount: account.Name, AccountUID: account.UID, Port: 8443, NativePort: 9444, NativeBootstrap: fleet.OwnerBootstrapProfile, NativeCandidateLimit: fleet.OwnerRegistrationsPerPool}
	accepted := fleet.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: in.ConfigurationUID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: in.KeyService.Roots}
	files, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	s, err := NewInstalledOwnerProviderEffects(context.Background(), in, files, reader, &postgres.OwnerConfigurations{}, accepted)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	want, _ := json.Marshal(s.input)
	in.ProviderAuthentication.AuthMount = "replaced"
	in.Observation.Activation.Input.OwnerConfigurationUID = id(99)
	in.KeyService.Roots[0][0] ^= 1
	got, _ := json.Marshal(s.input)
	if !bytes.Equal(want, got) {
		t.Fatal("caller changed installed provider's retained original input")
	}
}
