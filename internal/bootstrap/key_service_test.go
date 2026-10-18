package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// keyServiceDownloadsFixture is a synthetic pinned worker profile in its own
// worker namespace of the key service's cluster, with no topology pins.
func keyServiceDownloadsFixture(c contracts.KeyServiceDeployment) *contracts.KeyServiceDownloads {
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	ref := func(name, n string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: id(n)}
	}
	return &contracts.KeyServiceDownloads{WorkerSource: ref("worker-profile", "10"),
		WorkerProfile: contracts.WorkerConfiguration{Format: "asservat-worker-configuration/v1", InstallationID: c.InstallationID, ClusterID: c.ClusterID, RecoveryEpoch: c.RecoveryEpoch, Revision: 1,
			Namespace: ref("asservat-downloads", "11"), ServiceAccount: ref("acquisition", "12"), PriorityClass: ref("acquisition", "13"),
			ControlConfig: contracts.LocalKeySecretReference{Name: "worker-control", UID: id("14"), SHA256: strings.Repeat("1", 64)},
			Image:         "synthetic.invalid/asservat@sha256:" + strings.Repeat("2", 64), ImagePullSecrets: []string{}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntimeSeconds: 60},
		ClusterCatalog:      contracts.OwnerPublicGuardedSource{Source: ref("cluster-catalog", "15"), Guard: contracts.OwnerDeploymentGuard{Name: "cluster-catalog-guard", PolicyUID: id("16"), PolicyGeneration: 1, BindingUID: id("17"), BindingResourceVersion: "3", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "installer"}}}},
		RetentionTopologies: []contracts.OwnerNativeTopology{}}
}

// ADR-204 decision 8: the Downloads section is optional; when present its
// pinned profile is the guarded source reader's own parse of the document,
// for workers outside the key service's namespace, and its pins are closed.
func TestKeyServiceDownloadsSectionIsOptionalAndClosed(t *testing.T) {
	read := func(c contracts.KeyServiceDeployment) (contracts.KeyServiceDeployment, error) {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "key-service.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		return readKeyServiceDeployment(context.Background(), root)
	}
	c := keyServiceTestDeployment(t)
	if got, err := read(c); err != nil || got.Downloads != nil {
		t.Fatal("key service without downloads", err)
	}
	c.Downloads = keyServiceDownloadsFixture(c)
	got, err := read(c)
	if err != nil || got.Downloads == nil {
		t.Fatal("key service with downloads", err)
	}
	profile, err := keyServiceWorkerProfile(got)
	if err != nil || !profile.Valid() || profile.Configuration.UID != c.Downloads.WorkerSource.UID || profile.Configuration.Generation != 1 || profile.NamespaceUID != c.Downloads.WorkerProfile.Namespace.UID {
		t.Fatal("pinned worker profile", err)
	}
	topology := func(cluster, name, n string) contracts.OwnerNativeTopology {
		return contracts.OwnerNativeTopology{TargetClusterID: cluster, Name: name, UID: "10000000-0000-4000-8000-0000000000" + n, SHA256: strings.Repeat("3", 64)}
	}
	for name, mutate := range map[string]func(*contracts.KeyServiceDownloads){
		"workers in the key service namespace": func(d *contracts.KeyServiceDownloads) { d.WorkerProfile.Namespace = c.Namespace },
		"profile of another cluster":           func(d *contracts.KeyServiceDownloads) { d.WorkerProfile.ClusterID = c.PermissionRootID },
		"profile of another installation":      func(d *contracts.KeyServiceDownloads) { d.WorkerProfile.InstallationID = c.ClusterID },
		"unpinned image":                       func(d *contracts.KeyServiceDownloads) { d.WorkerProfile.Image = "synthetic.invalid/asservat:latest" },
		"source without UID":                   func(d *contracts.KeyServiceDownloads) { d.WorkerSource.UID = "worker-profile" },
		"catalog guard without administrators": func(d *contracts.KeyServiceDownloads) { d.ClusterCatalog.Guard.Administrators = nil },
		"duplicate topology cluster": func(d *contracts.KeyServiceDownloads) {
			d.RetentionTopologies = []contracts.OwnerNativeTopology{topology(c.ClusterID, "first", "20"), topology(c.ClusterID, "second", "21")}
		},
		"empty topology digest": func(d *contracts.KeyServiceDownloads) {
			d.RetentionTopologies = []contracts.OwnerNativeTopology{topology(c.ClusterID, "first", "20")}
			d.RetentionTopologies[0].SHA256 = strings.Repeat("0", 64)
		},
	} {
		v := c
		v.Downloads = keyServiceDownloadsFixture(c)
		mutate(v.Downloads)
		if _, err := read(v); err == nil {
			t.Fatal("accepted:", name)
		}
	}
	// The section is closed like the rest of the input.
	dir := t.TempDir()
	writeOwnerJSON(t, dir, "key-service.json", c)
	raw, err := os.ReadFile(filepath.Join(dir, "key-service.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "key-service.json"), []byte(strings.Replace(string(raw), `"downloads":{`, `"downloads":{"profile":{},`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = readKeyServiceDeployment(context.Background(), root); err == nil {
		t.Fatal("unknown downloads field accepted")
	}
}

// Catalog slots add their own fixed-name pins to the input's; a slot pin for
// another cluster or name, or a cluster named twice, is refused.
func TestKeyServiceTopologyPinsUnionTheCatalog(t *testing.T) {
	c := keyServiceTestDeployment(t)
	c.Downloads = keyServiceDownloadsFixture(c)
	region := "10000000-0000-4000-8000-000000000030"
	slot := contracts.OwnerNativeTopology{TargetClusterID: region, Name: contracts.OwnerClusterSourceName(c.InstallationID, 1, "topology"), UID: "10000000-0000-4000-8000-000000000031", SHA256: strings.Repeat("4", 64)}
	c.Downloads.RetentionTopologies = []contracts.OwnerNativeTopology{{TargetClusterID: c.ClusterID, Name: "hub-topology", UID: "10000000-0000-4000-8000-000000000032", SHA256: strings.Repeat("5", 64)}}
	pins, err := keyServiceTopologyPins(c, []contracts.OwnerPublicCluster{{ClusterID: region, Topology: slot}})
	if err != nil || len(pins) != 2 || pins[1].TargetClusterID != region || pins[1].Name != slot.Name || pins[1].ContentDigest[0] != 0x44 {
		t.Fatal("catalog pins", err, pins)
	}
	for name, cluster := range map[string]contracts.OwnerPublicCluster{
		"slot pin for another cluster": {ClusterID: c.ClusterID, Topology: slot},
		"slot pin under another name":  {ClusterID: region, Topology: contracts.OwnerNativeTopology{TargetClusterID: region, Name: "chosen", UID: slot.UID, SHA256: slot.SHA256}},
		"cluster pinned twice":         {ClusterID: c.ClusterID, Topology: contracts.OwnerNativeTopology{TargetClusterID: c.ClusterID, Name: contracts.OwnerClusterSourceName(c.InstallationID, 1, "topology"), UID: slot.UID, SHA256: slot.SHA256}},
	} {
		if _, err := keyServiceTopologyPins(c, []contracts.OwnerPublicCluster{cluster}); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}

type recordingKeyAuthority struct{ called bool }

func (a *recordingKeyAuthority) Resolve(context.Context, authorization.KeyPeer, authorization.KeyRequestInfo) (authorization.KeyOperationPermit, error) {
	a.called = true
	return authorization.KeyOperationPermit{}, errors.New("synthetic authority")
}

// Without downloads the authority map is unchanged: an acquisition peer's
// unwrap has no entry and never reaches the verifier authority. With them,
// the acquisition role resolves to exactly the native download key authority.
func TestKeyServiceAuthoritiesAddAcquisitionOnlyWithDownloads(t *testing.T) {
	wraps, verifier := &recordingKeyAuthority{}, &recordingKeyAuthority{}
	plain := keyServiceAuthorities(wraps, verifier, nil)
	keys := make([]string, 0, len(plain))
	for k := range plain {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"unwrap/verifier", "wrap"}) {
		t.Fatal("authority map without downloads changed", keys)
	}
	if _, err := plain.Resolve(context.Background(), authorization.KeyPeer{Role: "acquisition"}, authorization.KeyRequestInfo{Operation: "unwrap"}); !errors.Is(err, authapp.ErrKeyDenied) || verifier.called || wraps.called {
		t.Fatal("acquisition unwrap reached another authority without downloads", err)
	}
	native := &postgres.NativeKeyAuthority{}
	downloads := keyServiceAuthorities(wraps, verifier, native)
	if len(downloads) != 3 || downloads["unwrap/acquisition"] != authapp.KeyOperationAuthorizer(native) || downloads["unwrap/verifier"] != authapp.KeyOperationAuthorizer(verifier) || downloads["wrap"] != authapp.KeyOperationAuthorizer(wraps) {
		t.Fatal("acquisition unwrap is not the native download key authority")
	}
}

func keyServiceTestDeployment(t *testing.T) contracts.KeyServiceDeployment {
	t.Helper()
	f, _, l := newRuntimeFixture(t)
	l.Close()
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	roots := [][]byte{f.ca.Raw}
	return contracts.KeyServiceDeployment{Format: contracts.KeyServiceDeploymentFormat, InstallationID: id("01"), ClusterID: id("02"), PermissionRootID: id("03"), Port: 9447,
		Namespace: contracts.WorkerObjectReference{Name: "asservat-keys", UID: id("04")}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid", Roots: roots},
		KeySource: contracts.WorkerObjectReference{Name: "artifact-keys", UID: id("05")}, KeyID: "artifact", RecoveryEpoch: id("06"),
		Postgres:       contracts.OwnerPostgresEndpoint{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat", MaxConnections: 1},
		KeyClientRoots: roots, ConnectorClientRoots: roots, Concurrency: 4}
}

// ADR-176: the key service's inputs are closed; an invalid section stops it.
func TestKeyServiceDeploymentInputsAreClosed(t *testing.T) {
	read := func(c contracts.KeyServiceDeployment) error {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "key-service.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readKeyServiceDeployment(context.Background(), root)
		return err
	}
	if err := read(keyServiceTestDeployment(t)); err != nil {
		t.Fatal("valid key service input", err)
	}
	for name, mutate := range map[string]func(*contracts.KeyServiceDeployment){
		"downloads without topology list": func(c *contracts.KeyServiceDeployment) {
			c.Downloads = keyServiceDownloadsFixture(*c)
			c.Downloads.RetentionTopologies = nil
		},
		"pool above one connection": func(c *contracts.KeyServiceDeployment) { c.Postgres.MaxConnections = 2 },
		"no connector roots":        func(c *contracts.KeyServiceDeployment) { c.ConnectorClientRoots = nil },
		"epoch not a UUID":          func(c *contracts.KeyServiceDeployment) { c.RecoveryEpoch = "epoch" },
		"unsafe key ID":             func(c *contracts.KeyServiceDeployment) { c.KeyID = "../root" },
		"no key-client roots":       func(c *contracts.KeyServiceDeployment) { c.KeyClientRoots = nil },
		"plain HTTP Kubernetes":     func(c *contracts.KeyServiceDeployment) { c.Kubernetes.Endpoint = "http://api.synthetic.invalid" },
		"unbounded concurrency":     func(c *contracts.KeyServiceDeployment) { c.Concurrency = 65 },
		"other format":              func(c *contracts.KeyServiceDeployment) { c.Format = "asservat-key-service-deployment/v0" },
	} {
		c := keyServiceTestDeployment(t)
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
}
