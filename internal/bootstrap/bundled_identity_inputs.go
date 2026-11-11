package bootstrap

import (
	"bytes"
	"context"
	"os"
	"slices"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

const bundledKeycloakIdentitySource = "bundledKeycloak"
const bundledKeycloakSettingsFile = "keycloak-settings.json"

// Only public, retained installation identity is selected here. Realm/client
// secrets and bootstrap-administrator credentials are not projected to these
// phases. The ordinary permission configuration still decides evidence rights.
func readBundledIdentity(ctx context.Context, files *os.Root, namespace string) (contracts.SmallKeycloakSettings, string, error) {
	var zero contracts.SmallKeycloakSettings
	raw, err := mounts.Read(ctx, files, bundledKeycloakSettingsFile, contracts.SmallServicesMaxBytes)
	if err != nil {
		return zero, "", mounts.ErrUnavailable
	}
	s, err := contracts.DecodeSmallKeycloakSettings(bytes.NewReader(raw))
	clear(raw)
	if err != nil || !validSmallKeycloakSettings(s) || s.Namespace != namespace {
		return zero, "", mounts.ErrUnavailable
	}
	group, err := mounts.Read(ctx, files, contracts.SmallKeycloakUsersGroup, 64)
	if err != nil || !authorization.UUID(string(group)) {
		return zero, "", mounts.ErrUnavailable
	}
	return s, string(group), nil
}

func resolveInitialBootstrapIdentity(ctx context.Context, files *os.Root, input *contracts.InitialBootstrapInput) error {
	if input.IdentitySource == "" {
		return nil
	}
	if input.IdentitySource != bundledKeycloakIdentitySource {
		return mounts.ErrUnavailable
	}
	s, group, err := readBundledIdentity(ctx, files, input.BootstrapNamespace)
	if err != nil || s.SecretName != input.Name+"-keycloak-state" || input.Fleet.Issuer != s.Hostname+"/realms/"+s.Realm || !slices.Contains(input.Fleet.Clients, s.ConsoleClientID) {
		return mounts.ErrUnavailable
	}
	if !slices.Contains(input.Fleet.Groups, group) {
		input.Fleet.Groups = append(input.Fleet.Groups, group)
	}
	input.IdentitySource = ""
	return nil
}

func resolveInstallerContinuationIdentity(ctx context.Context, files *os.Root, input *contracts.InstallerContinuation) error {
	if input.IdentitySource == "" {
		return nil
	}
	if input.IdentitySource != bundledKeycloakIdentitySource || input.Public == nil {
		return mounts.ErrUnavailable
	}
	s, group, err := readBundledIdentity(ctx, files, input.Namespace)
	p := input.Public
	if err != nil || p.Origin != s.Origin || p.Issuer != s.Hostname+"/realms/"+s.Realm || p.ClientID != s.ConsoleClientID {
		return mounts.ErrUnavailable
	}
	if !slices.Contains(p.EligibleGroups, group) {
		p.EligibleGroups = append(p.EligibleGroups, group)
	}
	input.IdentitySource = ""
	return nil
}
