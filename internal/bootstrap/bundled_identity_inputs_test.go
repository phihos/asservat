package bootstrap

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func TestBundledIdentityFeedsTheSameRetainedGroupToBootstrapAndPublicSettings(t *testing.T) {
	s := smallKeycloakTestSettings()
	material, err := BuildSmallKeycloakMaterial(s, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for key, file := range map[string]string{contracts.SmallKeycloakSettingsFile: bundledKeycloakSettingsFile, contracts.SmallKeycloakUsersGroup: contracts.SmallKeycloakUsersGroup} {
		if err := os.WriteFile(filepath.Join(dir, file), material.Data[key], 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	v, ca := smallBootstrapInput(t)
	v.Name, v.BootstrapNamespace = "trial", s.Namespace
	v.IdentitySource = bundledKeycloakIdentitySource
	v.Fleet.Issuer = s.Hostname + "/realms/" + s.Realm
	v.Fleet.Clients = []string{s.ConsoleClientID}
	v.Postgres.RootsSource, v.Postgres.RootsPEM = "", string(ca)
	if _, err := providerconfig.CompileInitialBootstrapInput(v, nil, nil, time.Now()); err == nil {
		t.Fatal("unresolved identity reached canonical compiler")
	}
	if err := resolveInitialBootstrapIdentity(t.Context(), files, &v); err != nil {
		t.Fatal(err)
	}
	group := string(material.Data[contracts.SmallKeycloakUsersGroup])
	if v.IdentitySource != "" || !reflect.DeepEqual(v.Fleet.Groups, []string{group}) {
		t.Fatal("bootstrap identity differs from retained realm")
	}
	p := contracts.InstallerContinuation{Namespace: s.Namespace, IdentitySource: bundledKeycloakIdentitySource, Public: &contracts.InstallerPublicSettings{Origin: s.Origin, Issuer: v.Fleet.Issuer, ClientID: s.ConsoleClientID}}
	if err := resolveInstallerContinuationIdentity(t.Context(), files, &p); err != nil || p.IdentitySource != "" || !reflect.DeepEqual(p.Public.EligibleGroups, v.Fleet.Groups) {
		t.Fatal("public settings differ from original root eligibility", err)
	}
	// Replay consumes the same public identity without duplicating grants.
	p.IdentitySource = bundledKeycloakIdentitySource
	if err := resolveInstallerContinuationIdentity(t.Context(), files, &p); err != nil || len(p.Public.EligibleGroups) != 1 {
		t.Fatal("replay changes eligibility", err)
	}
	for _, mode := range []string{"unknown", "issuer", "origin", "client", "missing-group", "changed-database"} {
		t.Run(mode, func(t *testing.T) {
			c := p
			pub := *p.Public
			c.Public = &pub
			c.IdentitySource = bundledKeycloakIdentitySource
			switch mode {
			case "unknown":
				c.IdentitySource = "external-file"
			case "issuer":
				c.Public.Issuer = "https://another.example/realms/asservat"
			case "origin":
				c.Public.Origin = "https://another.example"
			case "client":
				c.Public.ClientID = "another-client"
			case "missing-group":
				if err := os.Remove(filepath.Join(dir, contracts.SmallKeycloakUsersGroup)); err != nil {
					t.Fatal(err)
				}
				defer os.WriteFile(filepath.Join(dir, contracts.SmallKeycloakUsersGroup), material.Data[contracts.SmallKeycloakUsersGroup], 0600)
			case "changed-database":
				changed := s
				changed.Database.Host = "another-postgres.example"
				// A valid new target must not validate against original private
				// state; preparation would otherwise reset a populated realm.
				if ValidateSmallKeycloakMaterial(changed, material) == nil {
					t.Fatal("retained state accepted a new database target")
				}
				return
			}
			if err := resolveInstallerContinuationIdentity(t.Context(), files, &c); err == nil {
				t.Fatal("ambiguous/unavailable identity source accepted")
			}
		})
	}
}
