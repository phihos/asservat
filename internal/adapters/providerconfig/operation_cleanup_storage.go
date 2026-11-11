package providerconfig

import "asservat.local/asservat/internal/contracts"

// These are requests to the operator's existing storage administration, not
// IAM provisioning or a claim that an unqualified backend enforces them.
type OperationCleanupStorageRequirements struct {
	Store                contracts.OwnerAuditStore        `json:"store"`
	Prefixes             []string                         `json:"prefixes"`
	Cleanup              OperationCleanupStoragePrincipal `json:"cleanup"`
	Verify               OperationCleanupStoragePrincipal `json:"verify"`
	Versioning           string                           `json:"versioning"`
	BackendQualification string                           `json:"backendQualification"`
}

type OperationCleanupStoragePrincipal struct {
	SecretKey        string   `json:"secretKey"`
	BucketOperations []string `json:"bucketOperations"`
	ObjectOperations []string `json:"objectOperations"`
	DeniedOperations []string `json:"deniedOperations"`
	// Writes have their own exact object selector, separate from the broader
	// inventory/read/delete prefix. The writer must send If-None-Match: *.
	WriteObjects []OperationCleanupObjectWrite `json:"writeObjects,omitempty"`
}

type OperationCleanupObjectWrite struct {
	Operation          string `json:"operation"`
	Pattern            string `json:"pattern"`
	RequestIfNoneMatch string `json:"requestIfNoneMatch"`
}

func OperationCleanupStorageRequirementsFor(store contracts.OwnerAuditStore, root string) *OperationCleanupStorageRequirements {
	return &OperationCleanupStorageRequirements{
		Store: store, Prefixes: []string{"operation-audit/v1/" + root + "/"}, Versioning: "Enabled", BackendQualification: "required",
		Cleanup: OperationCleanupStoragePrincipal{SecretKey: contracts.InstallerInboxCleanupAuditCredential,
			BucketOperations: []string{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads"},
			ObjectOperations: []string{"GetObject", "GetObjectVersion", "DeleteObjectVersion", "AbortMultipartUpload", "ListMultipartUploadParts"},
			DeniedOperations: []string{"PutBucketVersioning", "PutBucketPolicy", "PutLifecycleConfiguration"},
			WriteObjects:     []OperationCleanupObjectWrite{{Operation: "PutObject", Pattern: "operation-audit/v1/" + root + "/*/deletion-certificate", RequestIfNoneMatch: "*"}}},
		Verify: OperationCleanupStoragePrincipal{SecretKey: contracts.InstallerInboxCleanupVerifyCredential,
			BucketOperations: []string{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads"},
			ObjectOperations: []string{"GetObject", "GetObjectVersion", "ListMultipartUploadParts"},
			DeniedOperations: []string{"PutObject", "DeleteObject", "DeleteObjectVersion", "AbortMultipartUpload", "PutBucketVersioning", "PutBucketPolicy", "PutLifecycleConfiguration"}},
	}
}
