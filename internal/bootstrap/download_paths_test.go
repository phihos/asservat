package bootstrap

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/privacy"
)

func pathID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// syntheticPathTemplate is a hub-local template (ADR-204 decision 3) with
// synthetic identities only.
func syntheticPathTemplate(hub string) contracts.DownloadEnvironmentPathTemplate {
	return contracts.DownloadEnvironmentPathTemplate{StoreID: pathID(20), StorageRegion: "synthetic-store", AcquisitionClusterID: hub, AcquisitionRegion: "synthetic-hub",
		ConnectorClusterID: hub, ConnectorRegion: "synthetic-hub", HubClusterID: hub, HubRegion: "synthetic-hub",
		WorkerConfiguration: contracts.DownloadEnvironmentRevision{UID: pathID(21), Generation: 1, SHA256: strings.Repeat("ab", 32)},
		HubConfiguration:    contracts.DownloadEnvironmentRevision{UID: pathID(22), Generation: 2, SHA256: strings.Repeat("cd", 32)}}
}

func pathsByID(t *testing.T, in []privacy.DownloadPath) map[string]privacy.DownloadPath {
	t.Helper()
	out := map[string]privacy.DownloadPath{}
	for _, p := range in {
		out[p.ID] = p
	}
	return out
}

// ADR-204 decision 4: the hub-api derives one path per catalog cluster, the
// capacity hub-worker one per regional qualification. For the same clusters,
// in any order, both union the same paths with the pinned ones.
func TestDownloadPathsDerivedIdenticallyByHubAPIAndCapacity(t *testing.T) {
	installation, hub, a, b := pathID(1), pathID(2), pathID(3), pathID(4)
	tmpl := syntheticPathTemplate(hub)
	pinned := contracts.DownloadPathFor(installation, tmpl, pathID(9))
	pinned.ID = pathID(10)
	catalog := contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: []contracts.OwnerPublicCluster{{ClusterID: a}, {ClusterID: b}}}
	regional := []app.CapacityNamespaceQualification{{ClusterID: b}, {ClusterID: a}}
	hubAPI, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{pinned}, &tmpl, catalogTargets(catalog))
	if err != nil {
		t.Fatal(err)
	}
	capacity, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{pinned}, &tmpl, regionalTargets(regional))
	if err != nil {
		t.Fatal(err)
	}
	x, y := pathsByID(t, hubAPI), pathsByID(t, capacity)
	if len(x) != 3 || !maps.Equal(x, y) {
		t.Fatal("hub-api and capacity derived different paths", x, y)
	}
	for _, target := range []string{a, b} {
		want := contracts.DownloadPathFor(installation, tmpl, target)
		got, ok := x[want.ID]
		if !ok || got.TargetClusterID != target || got.StoreID != tmpl.StoreID || got.AcquisitionClusterID != hub || got.ConnectorClusterID != hub || got.HubClusterID != hub ||
			got.WorkerConfiguration.UID != tmpl.WorkerConfiguration.UID || got.HubConfiguration.Generation != 2 {
			t.Fatal("derived path", target, got)
		}
	}
	if _, ok := x[pinned.ID]; !ok {
		t.Fatal("pinned path dropped")
	}
	// The join derives the same path for the joined cluster.
	owner := contracts.OwnerDeployment{InstallationID: installation, ClusterID: hub, PermissionRootID: pathID(5),
		Public: &contracts.OwnerPublicDeployment{DownloadEnvironment: contracts.OwnerPublicEnvironment{Source: contracts.WorkerObjectReference{Name: "synthetic-download-environment", UID: pathID(6)}, Paths: []contracts.DownloadEnvironmentPath{}, PathTemplate: &tmpl}}}
	joined, err := regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: a})
	if err != nil || joined == nil || joined.Path.ID != contracts.DownloadPathFor(installation, tmpl, a).ID || x[joined.Path.ID].ID != joined.Path.ID {
		t.Fatal("join path differs from the derived path", err)
	}
}

// Without a template the pinned paths are used as before and no target adds
// a path.
func TestDownloadPathsWithoutTemplateAreUnchanged(t *testing.T) {
	installation, hub := pathID(1), pathID(2)
	pinned := contracts.DownloadPathFor(installation, syntheticPathTemplate(hub), pathID(3))
	before, err := capacityRuntimeProcessingPaths([]contracts.DownloadEnvironmentPath{pinned})
	if err != nil {
		t.Fatal(err)
	}
	after, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{pinned}, nil, []string{pathID(4), pathID(5)})
	if err != nil || !slices.Equal(before, after) {
		t.Fatal("paths without a template changed", err)
	}
	if empty, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{}, nil, []string{pathID(4)}); err != nil || len(empty) != 0 {
		t.Fatal("an empty pinned set without a template gained a path", err)
	}
	if _, err := downloadEnvironmentPaths(installation, hub, nil, nil, nil); err == nil {
		t.Fatal("missing pinned paths accepted")
	}
	owner := contracts.OwnerDeployment{InstallationID: installation, ClusterID: hub, Public: &contracts.OwnerPublicDeployment{}}
	if d, err := regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: pathID(4), Capacity: &contracts.OwnerPublicClusterCapacity{}}); err != nil || d != nil {
		t.Fatal("a join without a template adds a path", err)
	}
}

// The template is validated strictly, even with no target; repeated targets
// and a pinned path with a derived ID are refused.
func TestDownloadPathTemplateRejects(t *testing.T) {
	installation, hub, target := pathID(1), pathID(2), pathID(3)
	other := pathID(7)
	for name, change := range map[string]func(*contracts.DownloadEnvironmentPathTemplate){
		"store":               func(v *contracts.DownloadEnvironmentPathTemplate) { v.StoreID = "store" },
		"storage region":      func(v *contracts.DownloadEnvironmentPathTemplate) { v.StorageRegion = "" },
		"long region":         func(v *contracts.DownloadEnvironmentPathTemplate) { v.StorageRegion = strings.Repeat("r", 64) },
		"acquisition cluster": func(v *contracts.DownloadEnvironmentPathTemplate) { v.AcquisitionClusterID = other },
		"connector cluster":   func(v *contracts.DownloadEnvironmentPathTemplate) { v.ConnectorClusterID = other },
		"hub cluster":         func(v *contracts.DownloadEnvironmentPathTemplate) { v.HubClusterID = other },
		"acquisition region":  func(v *contracts.DownloadEnvironmentPathTemplate) { v.AcquisitionRegion = "elsewhere" },
		"connector region":    func(v *contracts.DownloadEnvironmentPathTemplate) { v.ConnectorRegion = "elsewhere" },
		"worker uid":          func(v *contracts.DownloadEnvironmentPathTemplate) { v.WorkerConfiguration.UID = "worker" },
		"worker generation":   func(v *contracts.DownloadEnvironmentPathTemplate) { v.WorkerConfiguration.Generation = 0 },
		"worker digest": func(v *contracts.DownloadEnvironmentPathTemplate) {
			v.WorkerConfiguration.SHA256 = strings.Repeat("AB", 32)
		},
		"hub configuration uid":  func(v *contracts.DownloadEnvironmentPathTemplate) { v.HubConfiguration.UID = "" },
		"hub configuration hash": func(v *contracts.DownloadEnvironmentPathTemplate) { v.HubConfiguration.SHA256 = "ab" },
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := syntheticPathTemplate(hub)
			change(&tmpl)
			for _, targets := range [][]string{nil, {target}} {
				if _, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{}, &tmpl, targets); err == nil {
					t.Fatal("invalid template accepted", targets)
				}
			}
			owner := contracts.OwnerDeployment{InstallationID: installation, ClusterID: hub, PermissionRootID: pathID(5),
				Public: &contracts.OwnerPublicDeployment{DownloadEnvironment: contracts.OwnerPublicEnvironment{Source: contracts.WorkerObjectReference{Name: "synthetic-download-environment", UID: pathID(6)}, Paths: []contracts.DownloadEnvironmentPath{}, PathTemplate: &tmpl}}}
			if _, err := regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: target}); err == nil {
				t.Fatal("join accepted an invalid template")
			}
		})
	}
	tmpl := syntheticPathTemplate(hub)
	if _, err := downloadEnvironmentPaths(installation, pathID(8), []contracts.DownloadEnvironmentPath{}, &tmpl, nil); err == nil {
		t.Fatal("template for another hub cluster accepted")
	}
	if _, err := downloadEnvironmentPaths("installation", hub, []contracts.DownloadEnvironmentPath{}, &tmpl, nil); err == nil {
		t.Fatal("invalid installation accepted")
	}
	for name, targets := range map[string][]string{"repeated": {target, target}, "invalid": {"cluster"}} {
		if _, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{}, &tmpl, targets); err == nil {
			t.Fatal(name, "target accepted")
		}
	}
	derived := contracts.DownloadPathFor(installation, tmpl, target)
	for name, pinned := range map[string]contracts.DownloadEnvironmentPath{"duplicate": derived, "conflicting": func() contracts.DownloadEnvironmentPath { v := derived; v.TargetClusterID = other; return v }()} {
		if _, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{pinned}, &tmpl, []string{target}); err == nil {
			t.Fatal(name, "pinned path ID accepted beside the derived path")
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = pathID(100 + i)
	}
	if _, err := downloadEnvironmentPaths(installation, hub, []contracts.DownloadEnvironmentPath{}, &tmpl, many); err == nil {
		t.Fatal("more than 32 paths accepted")
	}
}

// The join adds the path to the hub-api's source always and to the capacity
// processing source only with a capacity section, the clusters the capacity
// hub-worker derives paths for.
func TestRegionalJoinDownloadSources(t *testing.T) {
	installation, hub, cluster := pathID(1), pathID(2), pathID(3)
	tmpl := syntheticPathTemplate(hub)
	source := contracts.WorkerObjectReference{Name: "synthetic-download-environment", UID: pathID(6)}
	owner := contracts.OwnerDeployment{InstallationID: installation, ClusterID: hub, PermissionRootID: pathID(5),
		Public: &contracts.OwnerPublicDeployment{DownloadEnvironment: contracts.OwnerPublicEnvironment{Source: source, Paths: []contracts.DownloadEnvironmentPath{}, PathTemplate: &tmpl}}}
	_, _, _, processing, _ := kube.CapacitySourceNames(installation)
	plain, err := regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: cluster})
	if err != nil || plain.RootID != owner.PermissionRootID || plain.Path != contracts.DownloadPathFor(installation, tmpl, cluster) || !slices.Equal(plain.Sources, []contracts.WorkerObjectReference{source}) {
		t.Fatal("join without capacity", err, plain)
	}
	withCapacity, err := regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: cluster, Capacity: &contracts.OwnerPublicClusterCapacity{}})
	if err != nil || withCapacity.Path != plain.Path || !slices.Equal(withCapacity.Sources, []contracts.WorkerObjectReference{source, {Name: processing}}) {
		t.Fatal("join with capacity", err, withCapacity)
	}
	owner.Public.DownloadEnvironment.Source = contracts.WorkerObjectReference{}
	if _, err = regionalJoinDownloads(owner, contracts.OwnerPublicCluster{ClusterID: cluster}); err == nil {
		t.Fatal("template without a pinned download environment accepted")
	}
}
