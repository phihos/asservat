package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func keyServiceTestConfig() contracts.KeyServiceConfig {
	return contracts.KeyServiceConfig{Name: "asservat", Namespace: "asservat", Port: 9447, Concurrency: 4,
		Postgres: contracts.ServicePostgres{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat"},
		OpenBao:  "https://bao.example"}
}

// The Downloads section is optional; the configured topologies may not name
// a cluster or ConfigMap twice. The key ID is the secrets Job's.
func TestKeyServiceInputsAreClosed(t *testing.T) {
	read := func(c contracts.KeyServiceConfig) (keyServiceInputs, error) {
		return readKeyServiceInputs(context.Background(), serviceTestConfigRoot(t, c), serviceTestIDsRoot(t, serviceTestIDs))
	}
	if got, err := read(keyServiceTestConfig()); err != nil || got.Downloads != nil || got.IssuerEpoch != serviceTestIDs.IssuerEpoch {
		t.Fatal("key service without downloads", err)
	}
	if s := artifactScope(serviceTestIDs.InstallationID); s.KeyID != "asservat-10000000000040008000000000000001-artifact" || !s.Valid() {
		t.Fatal("artifact scope", s)
	}
	withDownloads := func() contracts.KeyServiceConfig {
		c := keyServiceTestConfig()
		c.Downloads = &contracts.KeyServiceDownloadsConfig{}
		return c
	}
	if got, err := read(withDownloads()); err != nil || got.Downloads == nil {
		t.Fatal("key service with downloads", err)
	}
	for name, mutate := range map[string]func(*contracts.KeyServiceConfig){
		"plain HTTP provider":   func(c *contracts.KeyServiceConfig) { c.OpenBao = "http://bao.example" },
		"unbounded concurrency": func(c *contracts.KeyServiceConfig) { c.Concurrency = 65 },
		"no name":               func(c *contracts.KeyServiceConfig) { c.Name = "" },
	} {
		c := withDownloads()
		mutate(&c)
		if _, err := read(c); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

// The mounted artifact key carries no Kubernetes UID: its revision is the
// fixed source name with the highest key version as generation, so an
// additive rotation advances it.
func TestMountedKeySourceDerivesRevisionFromVersions(t *testing.T) {
	dir := t.TempDir()
	payload := `{"format":"asservat-local-keys/v1","installationID":"` + serviceTestIDs.InstallationID + `","purpose":"artifact","keyID":"artifact","activeVersion":2,"keys":[{"version":1,"material":"AAAA"},{"version":2,"material":"AQEB"}]}`
	if err := os.WriteFile(filepath.Join(dir, contracts.ArtifactKeyFile), []byte(payload), 0o400); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	scope := authorization.KeyScope{InstallationID: serviceTestIDs.InstallationID, Purpose: "artifact", KeyID: "artifact"}
	s := &mountedKeySource{files: root, scope: scope, cluster: serviceTestIDs.ClusterID, namespace: serviceTestIDs.PermissionRootID, epoch: serviceTestIDs.IssuerEpoch, now: time.Now}
	m, err := s.ReadKeyMaterial(context.Background())
	c := m.Configuration
	if err != nil || string(m.Payload) != payload || c.Revision.UID != mountedKeySourceID || c.Revision.Generation != 2 || c.SecretDigest != c.Revision.Digest || c.RecoveryEpoch != serviceTestIDs.IssuerEpoch || c.Suspended {
		t.Fatal("mounted key material", c, err)
	}
	if err = os.Remove(filepath.Join(dir, contracts.ArtifactKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, contracts.ArtifactKeyFile), []byte(`{"keys":[]}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadKeyMaterial(context.Background()); err == nil {
		t.Fatal("key material without a version accepted")
	}
}

type recordingKeyAuthority struct{ called bool }

func (a *recordingKeyAuthority) Resolve(context.Context, authorization.KeyPeer, authorization.KeyRequestInfo) (authorization.KeyOperationPermit, error) {
	a.called = true
	return authorization.KeyOperationPermit{}, errors.New("synthetic authority")
}

// Without downloads the authority map holds only wraps: an acquisition
// peer's unwrap has no entry and never reaches the wrap authority. With them,
// the acquisition role resolves to exactly the native download key authority.
func TestKeyServiceAuthoritiesAddAcquisitionOnlyWithDownloads(t *testing.T) {
	wraps := &recordingKeyAuthority{}
	plain := keyServiceAuthorities(wraps, nil)
	if len(plain) != 1 || plain["wrap"] != authapp.KeyOperationAuthorizer(wraps) {
		t.Fatal("authority map without downloads changed", plain)
	}
	if _, err := plain.Resolve(context.Background(), authorization.KeyPeer{Role: "acquisition"}, authorization.KeyRequestInfo{Operation: "unwrap"}); !errors.Is(err, authapp.ErrKeyDenied) || wraps.called {
		t.Fatal("acquisition unwrap reached another authority without downloads", err)
	}
	native := &postgres.NativeKeyAuthority{}
	downloads := keyServiceAuthorities(wraps, native)
	if len(downloads) != 2 || downloads["unwrap/acquisition"] != authapp.KeyOperationAuthorizer(native) || downloads["wrap"] != authapp.KeyOperationAuthorizer(wraps) {
		t.Fatal("acquisition unwrap is not the native download key authority")
	}
}
