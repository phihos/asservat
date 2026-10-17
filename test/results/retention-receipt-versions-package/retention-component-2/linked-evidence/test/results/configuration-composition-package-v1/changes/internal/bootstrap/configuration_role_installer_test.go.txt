package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

type configurationRoleInstallerFiles struct {
	files     *os.Root
	directory string
}

func configurationRoleInstallerFixture(t *testing.T) (*configurationRoleInstallerFiles, contracts.ConfigurationRoleInstaller) {
	t.Helper()
	authority, _, listener := newRuntimeFixture(t)
	listener.Close()
	directory := t.TempDir()
	files, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close() })
	f := &configurationRoleInstallerFiles{files: files, directory: directory}
	roots := [][]byte{authority.ca.Raw}
	id := func(n int) string { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
	ref := func(name string, n int) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: id(n)}
	}
	guard := func(name string, n int) contracts.OwnerDeploymentGuard {
		return contracts.OwnerDeploymentGuard{Name: name, PolicyUID: id(n), BindingUID: id(n + 1), PolicyGeneration: 1, BindingResourceVersion: "10", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "installer"}}}
	}
	return f, contracts.ConfigurationRoleInstaller{
		Format: contracts.ConfigurationRoleInstallerFormat,
		Roles: contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat,
			InstallationID: id(1), InitialClaimID: id(2), ClusterID: id(3),
			Namespace: ref("control", 4), Deployment: ref("hub-worker", 5),
			ServiceAccount: ref("hub-worker", 6), FleetSource: ref("fleet", 7),
			OwnerSource: ref("owner", 8), LayoutDigest: postgres.ConfigurationRuntimeRoleLayoutDigest()},
		OwnerDeployment: ref("hub", 9), WorkloadGuard: guard("control-guard", 10),
		FleetGuard: guard("fleet-guard", 12), OwnerGuard: guard("owner-guard", 14),
		ConfigurationProbes: []contracts.OwnerConfigurationProbe{},
		SchedulingLeases:    []contracts.OwnerSchedulingLease{},
		Kubernetes:          contracts.OwnerProviderEndpoint{Endpoint: "https://cluster.invalid", Roots: roots},
		Postgres:            contracts.OwnerPostgresEndpoint{Host: "postgres.invalid", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1},
	}
}

func TestConfigurationRoleInstallerRejectsAuthoritySubstitutionBeforeProviders(t *testing.T) {
	for _, mode := range []string{"valid", "unknown-grants", "unknown-credential-path", "public-layout", "missing-activation", "missing-native-pin", "same-source", "same-guard", "unbounded-connections", "missing-probes", "missing-root", "plaintext-provider", "symlink-escape"} {
		t.Run(mode, func(t *testing.T) {
			f, c := configurationRoleInstallerFixture(t)
			switch mode {
			case "public-layout":
				c.Roles.LayoutDigest = postgres.PublicRuntimeRoleLayoutDigest()
			case "missing-activation":
				c.Roles.InitialClaimID = ""
			case "missing-native-pin":
				c.WorkloadGuard.BindingUID = ""
			case "same-source":
				c.Roles.OwnerSource = c.Roles.FleetSource
			case "same-guard":
				c.OwnerGuard.Name = c.FleetGuard.Name
			case "unbounded-connections":
				c.Postgres.MaxConnections = 4
			case "missing-probes":
				c.ConfigurationProbes = nil
			case "missing-root":
				c.Postgres.Roots = nil
			case "plaintext-provider":
				c.Kubernetes.Endpoint = "http://cluster.invalid"
			}
			b, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-grants" {
				b = append(b[:len(b)-1], []byte(`,"grants":["ALL"]}`)...)
			}
			if mode == "unknown-credential-path" {
				b = append(b[:len(b)-1], []byte(`,"sqlFile":"/tmp/admin.json"}`)...)
			}
			decoded, err := contracts.DecodeConfigurationRoleInstaller(strings.NewReader(string(b)))
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = configurationRoleInstallerPlan(decoded); err != nil {
					t.Fatal(err)
				}
				return
			}
			if mode != "symlink-escape" && err == nil {
				_, _, err = configurationRoleInstallerPlan(decoded)
			}
			if mode != "symlink-escape" && err == nil {
				t.Fatal("invalid privileged input accepted")
			}
			if mode == "symlink-escape" {
				outside := filepath.Join(t.TempDir(), "deployment.json")
				if err = os.WriteFile(outside, b, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, filepath.Join(f.directory, "deployment.json")); err != nil {
					t.Fatal(err)
				}
			} else if err = os.WriteFile(filepath.Join(f.directory, "deployment.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			_, err = provisionConfigurationRoles(t.Context(), f.files)
			if !errors.Is(err, mounts.ErrUnavailable) || err != configurationRoleInputInvalid {
				t.Fatal("invalid input reached a provider phase", err)
			}
		})
	}
}

func TestConfigurationRoleInstallerRemedyDiscardsPrivateFailure(t *testing.T) {
	private := "password=private token=private postgres://private SELECT secret"
	for _, err := range []error{errors.New(private), fmt.Errorf("%s: %w", private, configurationRoleSQLUnavailable)} {
		out := ConfigurationRoleInstallerRemedy(err)
		if strings.Contains(out, "private") || strings.Contains(out, "SELECT") || strings.Contains(out, "postgres://") {
			t.Fatal("private cause disclosed")
		}
	}
}
