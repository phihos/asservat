package contracts

import (
	"bytes"
	"encoding/json"
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

func TestProcessingOrganizationWireDistinguishesUndeclaredAndDeclaredNone(t *testing.T) {
	for _, declarations := range [][]ProcessingOrganization{nil, {}, {{ID: "org-1", Name: "Declared organization", Activities: []string{"Storage"}, Regions: []string{}}}} {
		input := DownloadEnvironmentSettings{Processors: declarations}
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"processors"`)) != (declarations != nil) {
			t.Fatal("optional declarations changed wire meaning", string(raw))
		}
		var decoded DownloadEnvironmentSettings
		if err := json.Unmarshal(raw, &decoded); err != nil || (decoded.Processors == nil) != (declarations == nil) || len(decoded.Processors) != len(declarations) {
			t.Fatal("declarations did not round trip", err)
		}
	}
}
