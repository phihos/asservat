package contracts

import "testing"

func TestInitialRuntimeLayoutsRejectMixedIncompleteProfiles(t *testing.T) {
	workers := []string{"", HubWorkerInstalledLayout, HubWorkerProviderInstalledLayout, "other"}
	owners := []string{"", OwnerInstalledLayout, OwnerProviderInstalledLayout, "other"}
	valid := map[[2]string]bool{
		{"", ""}:                       true,
		{HubWorkerInstalledLayout, ""}: true,
		{HubWorkerInstalledLayout, OwnerInstalledLayout}:                 true,
		{HubWorkerProviderInstalledLayout, OwnerProviderInstalledLayout}: true,
	}
	for _, worker := range workers {
		for _, owner := range owners {
			if InitialRuntimeLayoutsSupported(worker, owner) != valid[[2]string{worker, owner}] {
				t.Errorf("unexpected original layout pair %q / %q", worker, owner)
			}
		}
	}
}
