package integration

import "testing"

func TestInstalledManualProfileHeapBrowserSelectsOneReviewedClient(t *testing.T) {
	for _, tc := range []struct{ focus, variant, want string }{
		{"manual-profile", "heap", "console"}, {"manual-profile", "cpu", "mcp"}, {"manual-profile", "trace", "mcp"}, {"profile-comparison", "cpu", "mcp"}, {"profile-comparison", "accepted-heavy", "mcp"}, {"manual-arguments", "cpu", "mcp"},
	} {
		t.Run(tc.focus+"/"+tc.variant, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			t.Setenv("ASSERVAT_PROFILE_VARIANT", tc.variant)
			if got := installedProfileResultClient(); got != tc.want {
				t.Fatal("one selected result client changed", got, tc.want)
			}
		})
	}
}
