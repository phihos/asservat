package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestTargetDiscoveryCursorBindsCaptureArtifactVersionAndSection(t *testing.T) {
	capture := "10000000-0000-4000-8000-000000000001"
	artifactID := "10000000-0000-4000-8000-000000000002"
	version := artifact.Digest{1}
	p := TargetDiscoveryPage{CaptureID: capture, ArtifactID: artifactID, Version: version, Section: "processes", Total: 3, Processes: make([]TargetDiscoveryProcess, 2)}
	cursor := p.Next(1)
	w, err := NormalizeTargetDiscoveryWindow(TargetDiscoveryRequest{CaptureID: capture, Section: "processes", Cursor: cursor, Limit: 100})
	if err != nil || w.Start != 1 || !w.Matches(capture, artifactID, version) {
		t.Fatal("source-bound continuation", err)
	}
	for _, change := range []string{"capture", "artifact", "version", "section"} {
		c, a, v, x := capture, artifactID, version, w
		switch change {
		case "capture":
			c = artifactID
		case "artifact":
			a = capture
		case "version":
			v[0]++
		case "section":
			x.Section = "summary"
		}
		if x.Matches(c, a, v) {
			t.Fatal("cursor crossed", change)
		}
	}
	for _, bad := range []string{"1", "01:00000000000000000000000000000000", "-1:00000000000000000000000000000000", "256:00000000000000000000000000000000", "1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := NormalizeTargetDiscoveryWindow(TargetDiscoveryRequest{CaptureID: capture, Section: "processes", Cursor: bad}); err == nil {
			t.Fatal("noncanonical cursor accepted", bad)
		}
	}
	if p.Next(0) != "" || p.Next(3) != "" {
		t.Fatal("cursor skips undisclosed rows")
	}
	p.Section = "summary"
	if p.Next(1) != "" {
		t.Fatal("summary invented row cursor")
	}
}
