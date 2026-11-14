package integration

import (
	"errors"
	"testing"
)

// Resolve the physical API once, before any installation plan or effect. The
// descriptor remains factual: logical region 1 never overwrites cluster 1.
func installerContextRegionalIndex(helmContext bool, focus, topology string, clusters int) (int, error) {
	if topology != "" && topology != "separate-api" && topology != "same-api" {
		return 0, errors.New("unknown Helm context topology")
	}
	if topology != "" && !helmContext || helmContext && focus != "journey" {
		return 0, errors.New("explicit topology requires the actual Helm context journey")
	}
	index := 1
	if topology == "same-api" {
		index = 0
	}
	if clusters <= index {
		return 0, errors.New("selected physical API is absent from the original fixture")
	}
	return index, nil
}

func TestInstallerContextTopologySelectsOriginalAPI(t *testing.T) {
	for _, tc := range []struct {
		name, topology, focus string
		helm                  bool
		clusters, want        int
		refused               bool
	}{
		{name: "legacy", clusters: 2, want: 1},
		{name: "default Helm", helm: true, focus: "journey", clusters: 2, want: 1},
		{name: "explicit separate", helm: true, focus: "journey", topology: "separate-api", clusters: 2, want: 1},
		{name: "same with unused cluster", helm: true, focus: "journey", topology: "same-api", clusters: 2},
		{name: "one physical cluster", helm: true, focus: "journey", topology: "same-api", clusters: 1},
		{name: "missing separate API", helm: true, focus: "journey", clusters: 1, refused: true},
		{name: "unknown", helm: true, focus: "journey", topology: "combined", clusters: 2, refused: true},
		{name: "ordinary runtime", topology: "same-api", clusters: 2, refused: true},
		{name: "explicit separate without Helm", topology: "separate-api", clusters: 2, refused: true},
		{name: "other focus", helm: true, focus: "browser", topology: "same-api", clusters: 2, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := installerContextRegionalIndex(tc.helm, tc.focus, tc.topology, tc.clusters)
			if (err != nil) != tc.refused || err == nil && got != tc.want {
				t.Fatal("topology selection", got, err)
			}
		})
	}
}
