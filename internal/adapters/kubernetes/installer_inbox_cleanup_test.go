package kubernetes

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInstallerInboxCleanupCarriesOnlySeparateStorageMaterial(t *testing.T) {
	_, config := newDownloadWorkerAPI(t)
	ctx, installation := context.Background(), ownerID(1)
	material := map[string][]byte{
		contracts.InstallerInboxCleanupAuditCredential:  []byte(`{"accessKeyID":"cleanup","secretAccessKey":"synthetic-cleanup","sessionToken":""}`),
		contracts.InstallerInboxCleanupVerifyCredential: []byte(`{"accessKeyID":"verify","secretAccessKey":"synthetic-verify","sessionToken":""}`),
	}
	write := func(phase int, input map[string][]byte) error {
		return WriteInstallerInbox(ctx, config, "release", installation, phase, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, input)
	}
	if err := write(3, material); err != nil {
		t.Fatal(err)
	}
	inbox, err := ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || string(inbox.CleanupAuditCredential) != string(material[contracts.InstallerInboxCleanupAuditCredential]) || string(inbox.CleanupVerifyCredential) != string(material[contracts.InstallerInboxCleanupVerifyCredential]) {
		t.Fatal("lost cleanup credentials", err)
	}
	for _, phase := range []int{1, 2, 4} {
		if write(phase, material) == nil {
			t.Fatal("cleanup credentials admitted outside owner phase", phase)
		}
	}
	delete(material, contracts.InstallerInboxCleanupVerifyCredential)
	if write(3, material) == nil {
		t.Fatal("partial cleanup pair accepted")
	}
	if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	inbox, err = ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || inbox.CleanupAuditCredential != nil || inbox.CleanupVerifyCredential != nil {
		t.Fatal("absent cleanup pair retained old material", err)
	}
}
