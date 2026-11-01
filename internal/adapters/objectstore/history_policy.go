package objectstore

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"strings"
)

// RegionalHistoryCapability is a provider configuration proposal, never a
// credential or runtime authority. The pinned Seaweed profile combines scoped
// Read/Write with explicit bucket-policy inventory/deletion boundaries.
type RegionalHistoryCapability struct {
	Format                 string          `json:"format"`
	Identity               string          `json:"identity"`
	Prefix                 string          `json:"prefix"`
	SeaweedIdentityActions []string        `json:"seaweedIdentityActions"`
	S3BucketPolicy         json.RawMessage `json:"s3BucketPolicy"`
}

func SeaweedHistoryCapability(bucket, root, cluster string) (RegionalHistoryCapability, error) {
	var out RegionalHistoryCapability
	if !identity.Text(bucket, 63) || len(bucket) < 3 || strings.ContainsAny(bucket, "/\\*?:[]") || !authorization.UUID(root) || !authorization.UUID(cluster) {
		return out, artifact.ErrInvalid
	}
	name := "regional-history-" + cluster
	prefix := "history/v1/" + root + "/" + cluster + "/"
	resource := "arn:aws:s3:::" + bucket
	principal := map[string]any{"AWS": "arn:aws:iam::000000000000:user/" + name}
	list := []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
	objects := []string{"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}
	policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Sid": "AllowHistoryObjects", "Effect": "Allow", "Principal": principal, "Action": objects, "Resource": resource + "/" + prefix + "*"},
		map[string]any{"Sid": "AllowHistoryInventory", "Effect": "Allow", "Principal": principal, "Action": list, "Resource": resource, "Condition": map[string]any{"StringLike": map[string]any{"s3:prefix": prefix + "*"}}},
		map[string]any{"Sid": "DenyForeignHistoryInventory", "Effect": "Deny", "Principal": principal, "Action": list, "Resource": resource, "Condition": map[string]any{"StringNotLike": map[string]any{"s3:prefix": prefix + "*"}}},
		map[string]any{"Sid": "DenyEvidenceAccess", "Effect": "Deny", "Principal": principal, "Action": objects, "Resource": resource + "/v1/*"},
		map[string]any{"Sid": "DenyHistoryAdministration", "Effect": "Deny", "Principal": principal, "Action": []string{"s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketAcl", "s3:DeleteBucket"}, "Resource": resource},
	}})
	if err != nil {
		return out, artifact.ErrInvalid
	}
	return RegionalHistoryCapability{Format: "regional-history-capability/v1", Identity: name, Prefix: prefix, SeaweedIdentityActions: []string{"Read:" + bucket + "/" + prefix + "*", "Write:" + bucket + "/" + prefix + "*", "List:" + bucket}, S3BucketPolicy: policy}, nil
}
