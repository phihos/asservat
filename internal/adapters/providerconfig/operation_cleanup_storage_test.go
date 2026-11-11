package providerconfig

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerCleanupStorageArtifactDoesNotNeedPublisherOrPromotion(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000001490"
	f.in.Public = nil
	f.in.PermissionRootID = "10000000-0000-4000-8000-000000001491"
	base, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var original, with struct {
		Apply   []ownerProviderSetupRequest          `json:"apply"`
		Inspect []string                             `json:"inspect"`
		Cleanup *OperationCleanupStorageRequirements `json:"operationCleanupStorage"`
	}
	if json.Unmarshal(base, &original) != nil || json.Unmarshal(b, &with) != nil || original.Cleanup != nil || with.Cleanup == nil {
		t.Fatal("missing optional storage description")
	}
	if !reflect.DeepEqual(original.Apply, with.Apply) || f.requests.Load() != 0 {
		t.Fatal("storage declaration added provider writes or performed I/O")
	}
	c := with.Cleanup
	if !reflect.DeepEqual(c.Store, f.in.AuditStore) || !slices.Equal(c.Prefixes, []string{"operation-audit/v1/" + f.in.PermissionRootID + "/"}) || c.Cleanup.SecretKey != contracts.InstallerInboxCleanupAuditCredential || c.Verify.SecretKey != contracts.InstallerInboxCleanupVerifyCredential {
		t.Fatal("cleanup scope differs from original owner audit scope")
	}
	if !slices.Contains(with.Inspect, f.in.KeyService.AuditMount+"/keys/"+contracts.ContextDeletionSigningKeyName(f.in.InstallationID)) {
		t.Fatal("phase3 cannot inspect selected cleanup signer")
	}
	if slices.Contains(c.Cleanup.ObjectOperations, "PutObject") || len(c.Cleanup.WriteObjects) != 1 || c.Cleanup.WriteObjects[0] != (OperationCleanupObjectWrite{Operation: "PutObject", Pattern: "operation-audit/v1/" + f.in.PermissionRootID + "/*/deletion-certificate", RequestIfNoneMatch: "*"}) || len(c.Verify.WriteObjects) != 0 {
		t.Fatal("write grant not confined to conditional certificate create")
	}
	for _, write := range []string{"PutObject", "DeleteObjectVersion", "AbortMultipartUpload"} {
		if !slices.Contains(c.Verify.DeniedOperations, write) || slices.Contains(c.Verify.ObjectOperations, write) {
			t.Fatal("independent verification has write authority", write)
		}
	}
	f.in.PermissionRootID = ""
	if _, err := OwnerProviderSetupArtifact(f.in, f.profile, f.pool, f.roots, time.Now(), nil, nil, nil, nil, true); err == nil {
		t.Fatal("cleanup emitted without original root")
	}
}
