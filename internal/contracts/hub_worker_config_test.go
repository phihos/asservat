package contracts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeHubWorkerConfigIgnoresKeyOrderAndRejectsUnknownFields(t *testing.T) {
	valid := `{"provider":{"roles":{"auditUnwrap":"u","auditWrap":"w"},"authMount":"m","audience":"a"},"format":"asservat-hub-worker-config/v1","namespace":"asservat"}`
	c, err := DecodeHubWorkerConfig(strings.NewReader(valid))
	if err != nil || c.Namespace != "asservat" || c.Provider.Roles.AuditWrap != "w" || c.Capacity != nil {
		t.Fatal("Helm-rendered config refused", err)
	}
	for name, raw := range map[string]string{
		"unknown":  `{"format":"asservat-hub-worker-config/v1","activation":{}}`,
		"format":   `{"format":"asservat-hub-worker-deployment/v1"}`,
		"trailing": `{"format":"asservat-hub-worker-config/v1"} {}`,
		"empty":    ``,
	} {
		if _, err := DecodeHubWorkerConfig(strings.NewReader(raw)); err == nil {
			t.Fatal("accepted", name)
		}
	}
}

func TestReadInstallationIDs(t *testing.T) {
	dir := t.TempDir()
	keys := []string{"installationID", "clusterID", "issuerEpoch", "permissionRootID", "browserRootID", "sessionEpoch", "roleSetupID", "peerID"}
	for i, k := range keys {
		v := "10000000-0000-4000-8000-00000000000" + string(rune('1'+i)) + "\n"
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ids, err := ReadInstallationIDs(root)
	if err != nil || ids.InstallationID != "10000000-0000-4000-8000-000000000001" || ids.PeerID != "10000000-0000-4000-8000-000000000008" {
		t.Fatal("generated IDs not read", err, ids)
	}
	for _, bad := range []string{"not-a-uuid", "10000000-0000-4000-8000-00000000000A"} {
		if err := os.WriteFile(filepath.Join(dir, "clusterID"), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadInstallationIDs(root); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if err := os.Remove(filepath.Join(dir, "clusterID")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInstallationIDs(root); err == nil {
		t.Fatal("accepted a missing key")
	}
}
