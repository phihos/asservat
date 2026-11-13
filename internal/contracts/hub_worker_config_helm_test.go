package contracts

import (
	"os"
	"testing"
)

// TestHubWorkerConfigRendered decodes the Helm-rendered config.json with all
// three sections that scripts/test-helm-hub-worker.py writes to the path in
// ASSERVAT_HUB_WORKER_CONFIG.
func TestHubWorkerConfigRendered(t *testing.T) {
	path := os.Getenv("ASSERVAT_HUB_WORKER_CONFIG")
	if path == "" {
		t.Skip("set by scripts/test-helm-hub-worker.py")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := DecodeHubWorkerConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if c.Capacity == nil || c.Cleanup == nil || c.Permission == nil || c.Provider.ContextDeletionSigning.Key == "" || c.Provider.WorkerConfigurationAudit.Key == "" {
		t.Fatalf("sections missing: %+v", c)
	}
}
