package providerconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-205 decision 4: the phase-3 artifact names the context deletion
// child's own evidence credential, list and delete below v1/ only, with no
// provider request; an artifact without it is byte-identical to before.
func TestOwnerProviderArtifactNamesEvidenceDeleteCredential(t *testing.T) {
	f := newSetupFixture(t)
	f.in.ConfigurationUID = "10000000-0000-4000-8000-000000002051"
	in := f.in
	in.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "public-transit", Name: "work"},
		WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: "10000000-0000-4000-8000-000000002052"}}
	store := &contracts.InstallerEvidenceStore{Endpoint: "https://store.synthetic.invalid", Region: "synthetic-region", Bucket: "evidence"}
	now := time.Now()
	for _, downloads := range []*contracts.InstallerEvidenceStore{nil, store} {
		base, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, downloads, nil)
		if err != nil || bytes.Contains(base, []byte("evidenceDeleteStorage")) {
			t.Fatal("artifact without deletion changed", err)
		}
		b, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, downloads, store)
		if err != nil {
			t.Fatal(err)
		}
		// The section is the only difference.
		var with, without map[string]json.RawMessage
		if json.Unmarshal(b, &with) != nil || json.Unmarshal(base, &without) != nil {
			t.Fatal("artifact is not an object")
		}
		section := with["evidenceDeleteStorage"]
		delete(with, "evidenceDeleteStorage")
		stripped, err := ownerProviderCanonical(with)
		if err != nil || !bytes.Equal(stripped, base) {
			t.Fatal("deletion changed more than its own section")
		}
		var v struct {
			Endpoint, Region, Bucket, SecretKey, CredentialSchema, Semantics, BackendQualification string
			Prefixes, BucketOperations, ObjectOperations, DeniedOperations                         []string
		}
		decoder := json.NewDecoder(bytes.NewReader(section))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&v) != nil || v.Endpoint != store.Endpoint || v.Region != store.Region || v.Bucket != "evidence" || v.SecretKey != contracts.EvidenceDeleteCredentialFile ||
			v.CredentialSchema != "https://asservat.io/spec/v1/owner-credentials.schema.json" || v.BackendQualification != "required" ||
			!slices.Equal(v.Prefixes, []string{"v1/"}) ||
			!slices.Equal(v.BucketOperations, []string{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads"}) ||
			!slices.Equal(v.ObjectOperations, []string{"DeleteObject", "DeleteObjectVersion", "AbortMultipartUpload"}) {
			t.Fatal("evidence delete section", string(section))
		}
		for _, denied := range []string{"GetObject", "GetObjectVersion", "PutObject"} {
			if !slices.Contains(v.DeniedOperations, denied) || slices.Contains(v.ObjectOperations, denied) {
				t.Fatal("evidence delete credential may read or write", denied)
			}
		}
	}
	for name, s := range map[string]contracts.InstallerEvidenceStore{
		"endpoint": {Endpoint: "http://store.synthetic.invalid", Region: "synthetic-region", Bucket: "evidence"},
		"region":   {Endpoint: store.Endpoint, Bucket: "evidence"},
		"bucket":   {Endpoint: store.Endpoint, Region: "synthetic-region"},
	} {
		if _, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, store, &s); err == nil {
			t.Fatal("invalid evidence store accepted", name)
		}
	}
	in.Public = nil
	if _, err := OwnerProviderSetupArtifact(in, f.profile, f.pool, f.roots, now, nil, nil, nil, store); err == nil {
		t.Fatal("delete credential without a promoted owner accepted")
	}
}
