package kubernetes

import (
	"context"
	"reflect"
	"testing"
	"time"

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
		return WriteInstallerInbox(ctx, config, "release", installation, phase, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, InstallerInboxMaterial{Cleanup: input})
	}
	if err := write(3, material); err != nil {
		t.Fatal(err)
	}
	inbox, err := ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || string(inbox.CleanupAuditCredential) != string(material[contracts.InstallerInboxCleanupAuditCredential]) || string(inbox.CleanupVerifyCredential) != string(material[contracts.InstallerInboxCleanupVerifyCredential]) {
		t.Fatal("lost cleanup credentials", err)
	}
	cert, key, ca := installerServingTLSFixture(t, "federation.example.test", time.Now())
	serving := map[string][]byte{contracts.InstallerInboxFederationTLSCertificate: cert, contracts.InstallerInboxFederationTLSKey: key, contracts.InstallerInboxFederationTLSCA: ca}
	combined := InstallerInboxMaterial{Cleanup: material, ServingTLS: serving}
	if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, combined); err != nil {
		t.Fatal("combined phase-three material", err)
	}
	inbox, err = ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || !reflect.DeepEqual(inbox.ServingTLS, serving) || string(inbox.CleanupAuditCredential) != string(material[contracts.InstallerInboxCleanupAuditCredential]) || string(inbox.CleanupVerifyCredential) != string(material[contracts.InstallerInboxCleanupVerifyCredential]) {
		t.Fatal("merge lost one private material group", err)
	}
	for _, invalid := range []InstallerInboxMaterial{
		{Cleanup: map[string][]byte{}},
		{ServingTLS: map[string][]byte{}},
		{Cleanup: map[string][]byte{contracts.InstallerInboxCleanupAuditCredential: material[contracts.InstallerInboxCleanupAuditCredential], "unknown": []byte("refuse")}},
		{Cleanup: material, ServingTLS: map[string][]byte{"unknown": []byte("refuse")}},
		{ServingTLS: serving, Cleanup: map[string][]byte{contracts.InstallerInboxCleanupAuditCredential: material[contracts.InstallerInboxCleanupAuditCredential]}},
	} {
		if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, invalid); err == nil {
			t.Fatal("invalid private material group accepted")
		}
	}
	if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, nil, nil, combined, combined); err == nil {
		t.Fatal("multiple material selections accepted")
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
	if err != nil || inbox.CleanupAuditCredential != nil || inbox.CleanupVerifyCredential != nil || inbox.ServingTLS != nil {
		t.Fatal("absent cleanup pair retained old material", err)
	}
}
