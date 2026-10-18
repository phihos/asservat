package kubernetes

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-205 decision 4: the phase-3 inbox carries the context deletion child's
// evidence delete credential under its own key, apart from the download
// workers' read credential.
func TestInstallerInboxCarriesEvidenceDeleteCredential(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	ctx, installation := context.Background(), ownerID(1)
	downloads := []byte(`{"accessKeyID":"read","secretAccessKey":"read-secret","sessionToken":""}`)
	deletion := []byte(`{"accessKeyID":"delete","secretAccessKey":"delete-secret","sessionToken":""}`)
	if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, downloads, deletion); err != nil {
		t.Fatal(err)
	}
	stored := api.object("/api/v1/namespaces/release/secrets/" + contracts.InstallerInboxName(installation))["data"].(map[string]any)
	if _, ok := stored[contracts.InstallerInboxEvidenceDeleteCredential]; !ok || stored[contracts.InstallerInboxDownloadEvidenceCredential] == nil || stored[contracts.InstallerInboxEvidenceReadCredential] != nil {
		t.Fatal("inbox keys", stored)
	}
	inbox, err := ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || string(inbox.EvidenceDeleteCredential) != string(deletion) || string(inbox.DownloadEvidenceCredential) != string(downloads) {
		t.Fatal("inbox read", err)
	}
	if err = WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, downloads, nil); err != nil {
		t.Fatal(err)
	}
	if inbox, err = ReadInstallerInbox(ctx, config, "release", installation, 3); err != nil || inbox.EvidenceDeleteCredential != nil || inbox.DownloadEvidenceCredential == nil {
		t.Fatal("replaced inbox kept the delete credential", err)
	}
}
