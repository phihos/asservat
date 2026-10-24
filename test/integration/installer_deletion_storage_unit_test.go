package integration

import (
	"strings"
	"testing"
)

// Exact synthetic provider GET captured after native49, before any fault write:
// test/results/resumed-c62e02ac-native49/postmortem-bucket-policy.json.
// Keep the regional principal array and all original grants/denials unchanged.
const installedEvidenceNative49ProviderPolicy = `{"Version":"2012-10-17","Statement":[{"Sid":"DenyRegionalDeletion","Effect":"Deny","Principal":{"AWS":["arn:aws:iam::000000000000:user/regional-evidence"]},"Action":["s3:DeleteObject","s3:DeleteObjectVersion"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence/*"},{"Sid":"AllowEvidenceDeletion","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":["s3:DeleteObject","s3:DeleteObjectVersion","s3:AbortMultipartUpload"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence/v1/*"},{"Sid":"AllowEvidenceInventory","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":["s3:ListBucket","s3:ListBucketVersions","s3:ListBucketMultipartUploads"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence","Condition":{"StringLike":{"s3:prefix":"v1/*"}}},{"Sid":"DenyForeignInventory","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":["s3:ListBucket","s3:ListBucketVersions","s3:ListBucketMultipartUploads"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence","Condition":{"StringNotLike":{"s3:prefix":"v1/*"}}},{"Sid":"DenyEvidenceRead","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence/*"},{"Sid":"DenyEvidenceWrite","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence/*","Condition":{"StringNotEquals":{"s3:RequestMethod":"DELETE"}}},{"Sid":"DenyEvidenceAdministration","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/evidence-delete"},"Action":["s3:PutBucketVersioning","s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutLifecycleConfiguration","s3:PutBucketAcl","s3:DeleteBucket"],"Resource":"arn:aws:s3:::initial-bootstrap-chain-evidence"}]}`

func TestInstallerEvidenceBucketPolicyMatchesProviderReadback(t *testing.T) {
	t.Run("captured-provider-policy", func(t *testing.T) {
		got := installerEvidenceBucketPolicy("initial-bootstrap-chain-evidence")
		if !installedDeletionSamePolicy(got, installedEvidenceNative49ProviderPolicy) {
			t.Fatal("fixture policy differs from the captured provider read-back")
		}
	})
	t.Run("strict-scalar-array-distinction", func(t *testing.T) {
		array := strings.Replace(installedEvidenceNative49ProviderPolicy, `"Action":"s3:PutObject"`, `"Action":["s3:PutObject"]`, 1)
		if array == installedEvidenceNative49ProviderPolicy || installedDeletionSamePolicy(array, installedEvidenceNative49ProviderPolicy) {
			t.Fatal("policy comparison normalized the scalar/array distinction")
		}
	})
}
