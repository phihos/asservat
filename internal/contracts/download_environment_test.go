package contracts

import (
	"regexp"
	"testing"
)

func TestDownloadPathForIsStableAndDistinct(t *testing.T) {
	tmpl := DownloadEnvironmentPathTemplate{StoreID: "store", HubClusterID: "hub"}
	a := DownloadPathFor("installation", tmpl, "cluster-a")
	if a != DownloadPathFor("installation", tmpl, "cluster-a") || a.ID == DownloadPathFor("installation", tmpl, "cluster-b").ID || a.ID == DownloadPathFor("other", tmpl, "cluster-a").ID {
		t.Fatal("path IDs are not stable per installation and target")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(a.ID) || a.TargetClusterID != "cluster-a" || a.StoreID != "store" || a.HubClusterID != "hub" {
		t.Fatal("derived path", a)
	}
}
