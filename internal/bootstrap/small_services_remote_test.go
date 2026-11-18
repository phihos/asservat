package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const previousRegionalMutation = `{"Action":["s3:DeleteObject","s3:DeleteObjectVersion"],"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/asservat-regional-write-10000000-0000-4000-8000-000000000002"},"Resource":"arn:aws:s3:::asservat-evidence/*","Sid":"Asservate74c50bcabd40fdc29b9fc33Mutation"}`

// ADR-334: with the bundled object store every registered cluster gets its own
// regional capabilities, scoped to the cluster ID derived from its name; mode=hub generates no
// hub-cluster regional principal.
func TestSecretsHookScopesJoinedClusterCapabilities(t *testing.T) {
	const installation, hub, root = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002", "10000000-0000-4000-8000-000000000003"
	remote := contracts.RemoteClusterID(installation, "eu")
	api := fake.NewClientset()
	store := secretStore{api: api.CoreV1().Secrets("hub"), namespace: "hub"}
	admin, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: "10000000-0000-4000-8000-000000000009"})
	if err != nil {
		t.Fatal(err)
	}
	p := contracts.SecretsPlan{Name: "asservat", Mode: "hub", ObjectStore: &contracts.SmallSeaweedPlan{Namespace: "hub", Name: "asservat"}, RemoteClusters: []string{"eu"}}
	ids := installationIDs{"installationID": installation, "clusterID": hub, "permissionRootID": root}
	if err = store.objectStore(t.Context(), p, ids, admin); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"asservat-s3-regional-write-eu", "asservat-s3-regional-history-eu"} {
		if _, err = api.CoreV1().Secrets("hub").Get(t.Context(), name, meta.GetOptions{}); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err = api.CoreV1().Secrets("hub").Get(t.Context(), "asservat-s3-regional-write", meta.GetOptions{}); err == nil {
		t.Fatal("mode=hub generated the hub cluster's regional principal")
	}
	iam, err := api.CoreV1().Secrets("hub").Get(t.Context(), p.ObjectStore.IAMSecretName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	config := string(iam.Data[providerconfig.SeaweedConfigKey]) + string(iam.Data[SeaweedBucketPoliciesKey])
	if !strings.Contains(config, "asservat-regional-write-"+remote) || !strings.Contains(config, root+"/"+remote) || strings.Contains(config, "asservat-regional-write-"+hub) {
		t.Fatal("regional principals not scoped to the joined cluster")
	}
	// An installation upgrading from combined mode has this regional
	// statement in its existing desired policy. Grow its remote fleet.
	var policies map[string]json.RawMessage
	if err := json.Unmarshal(iam.Data[SeaweedBucketPoliciesKey], &policies); err != nil {
		t.Fatal(err)
	}
	policies["asservat-evidence"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[` + previousRegionalMutation + `]}`)
	iam.Data[SeaweedBucketPoliciesKey], err = json.Marshal(policies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.api.Update(t.Context(), iam, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	p.RemoteClusters = append(p.RemoteClusters, "us")
	if err := store.objectStore(t.Context(), p, ids, admin); err != nil {
		t.Fatal(err)
	}
	updated, err := store.api.Get(t.Context(), p.ObjectStore.IAMSecretName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	buckets := string(updated.Data[SeaweedBucketPoliciesKey])
	us := contracts.RemoteClusterID(installation, "us")
	if !strings.Contains(buckets, previousRegionalMutation) || strings.Contains(buckets, us) {
		t.Fatal("upgrade must retain the old regional bucket protection without adding one for the new cluster")
	}
	if !bytes.Contains(updated.Data[providerconfig.SeaweedConfigKey], []byte("asservat-regional-write-"+us)) {
		t.Fatal("new cluster missing from IAM")
	}

	// A previous fresh install wrote the desired Secret, then received HTTP
	// 400 for its oversized bucket policy. An upgrade can install from it.
	var oversized []string
	for i := range 100 {
		id := contracts.RemoteClusterID(installation, strconv.Itoa(i))
		principal := "asservat-regional-write-" + id
		hash := sha256.Sum256([]byte(principal))
		statement := strings.ReplaceAll(previousRegionalMutation, hub, id)
		oversized = append(oversized, strings.ReplaceAll(statement, "e74c50bcabd40fdc29b9fc33", hex.EncodeToString(hash[:12])))
	}
	policies["asservat-evidence"] = json.RawMessage(`{"Version":"2012-10-17","Statement":[` + strings.Join(oversized, ",") + `]}`)
	if len(policies["asservat-evidence"]) <= seaweedBucketPolicyBytes {
		t.Fatal("previous policy must exceed the provider limit")
	}
	updated.Data[SeaweedBucketPoliciesKey], err = json.Marshal(policies)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.api.Update(t.Context(), updated, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := store.objectStore(t.Context(), p, ids, admin); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.api.Get(t.Context(), p.ObjectStore.IAMSecretName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recovered.Data[SeaweedBucketPoliciesKey], &policies); err != nil {
		t.Fatal(err)
	}
	evidence := policies["asservat-evidence"]
	if len(evidence) == 0 || len(evidence) > seaweedBucketPolicyBytes || bytes.Contains(evidence, []byte("asservat-regional-")) {
		t.Fatal("retained an old policy which the provider could never have installed")
	}

}

// The previous compiler wrote this bucket Deny for the combined cluster.
// Keep that protection during the rollout and after a mode change: an old
// object-store process may still have the previous credentials loaded.
func TestSecretsHookPreservesExistingRegionalPolicy(t *testing.T) {
	const evidence = "asservat-evidence"
	const desired = `{"Version":"2012-10-17","Statement":[{"Sid":"Current"}]}`
	compiled := providerconfig.CompiledSeaweedStorage{Config: []byte("synthetic"), Policies: map[string]json.RawMessage{evidence: json.RawMessage(desired), "audit": json.RawMessage(desired)}}
	previous := []byte(`{"asservat-evidence":{"Version":"2012-10-17","Statement":[` + previousRegionalMutation + `,` +
		strings.ReplaceAll(previousRegionalMutation, "10000000-0000-4000-8000-000000000002", "not-a-cluster") + `,` +
		strings.ReplaceAll(previousRegionalMutation, "regional-write", "external") + `]},"audit":{"Version":"2012-10-17","Statement":[` + previousRegionalMutation + `]}}`)
	wantEvidence := strings.Replace(desired, "]}", ","+previousRegionalMutation+"]}", 1)
	for i := range 2 {
		data, err := compiledIAMData(compiled, evidence, previous)
		if err != nil {
			t.Fatal(err)
		}
		var policies map[string]json.RawMessage
		if json.Unmarshal(data[SeaweedBucketPoliciesKey], &policies) != nil || string(policies[evidence]) != wantEvidence || string(policies["audit"]) != desired {
			t.Fatal("unexpected retained bucket policy", i, string(data[SeaweedBucketPoliciesKey]))
		}
		previous = data[SeaweedBucketPoliciesKey]
	}
	// Include both documents and the carried statements in the Secret size.
	compiled.Config = make([]byte, core.MaxSecretSize-len(previous))
	data, err := compiledIAMData(compiled, evidence, previous)
	if err != nil || !bytes.Equal(data[SeaweedBucketPoliciesKey], previous) {
		t.Fatal("exactly the Secret data limit", err)
	}
	compiled.Config = append(compiled.Config, 0)
	if _, err := compiledIAMData(compiled, evidence, previous); err != secretsFailure("ObjectStoreIAMExceedsKubernetesSecretSize") {
		t.Fatal("oversize combined IAM data", err)
	}
}

// Run the same hook for the initial registration, withdrawal and replacement.
// The owned provider fixture optionally mounts the actual IAM produced at each step.
func TestRegionalStorageReRegistration(t *testing.T) {
	dir := os.Getenv("ASSERVAT_REGIONAL_STORAGE_FIXTURE_DIR")
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if dir != "" {
			if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	ids := installationIDs{"installationID": uuid.NewString(), "clusterID": uuid.NewString(), "permissionRootID": uuid.NewString()}
	root, installation := ids["permissionRootID"], ids["installationID"]
	admin, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: installation})
	if err != nil {
		t.Fatal(err)
	}
	api := fake.NewClientset()
	store := secretStore{api: api.CoreV1().Secrets("hub"), namespace: "hub"}
	p := contracts.SecretsPlan{Name: "asservat", Mode: "hub", ObjectStore: &contracts.SmallSeaweedPlan{Name: "asservat", Namespace: "hub"}}
	data := func(secret, key string) []byte {
		t.Helper()
		s, err := store.api.Get(t.Context(), secret, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return s.Data[key]
	}
	apply := func(file string, clusters ...string) []byte {
		t.Helper()
		p.RemoteClusters = clusters
		if err := store.objectStore(t.Context(), p, ids, admin); err != nil {
			t.Fatal(err)
		}
		config := data(p.ObjectStore.IAMSecretName(), providerconfig.SeaweedConfigKey)
		write(file, config, 0444)
		return config
	}
	credential := func(region, purpose string) contracts.SeaweedCredential {
		t.Helper()
		key, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(data(contracts.RemoteObjectStoreSecret(p.Name, purpose, region), contracts.ObjectStoreCredentialFile)))
		if err != nil {
			t.Fatal(err)
		}
		return contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: contracts.RemoteClusterID(installation, region)}, AccessKeyID: key.AccessKeyID, SecretAccessKey: key.SecretAccessKey}
	}
	apply("s3.json", "eu", "us")
	writer, history := credential("eu", "regional-write"), credential("eu", "regional-history")
	oldWriter, oldHistory := credential("us", "regional-write"), credential("us", "regional-history")
	revoked := apply("s3-revoked.json", "eu")
	returned := apply("s3-returned.json", "us", "eu")
	newWriter, newHistory := credential("us", "regional-write"), credential("us", "regional-history")
	if newWriter.AccessKeyID == oldWriter.AccessKeyID || newHistory.AccessKeyID == oldHistory.AccessKeyID || newWriter.SecretAccessKey == oldWriter.SecretAccessKey || newHistory.SecretAccessKey == oldHistory.SecretAccessKey {
		t.Fatal("re-registration restored withdrawn credentials")
	}
	for _, config := range [][]byte{revoked, returned} {
		if bytes.Contains(config, []byte(oldHistory.AccessKeyID)) || bytes.Contains(config, []byte(oldWriter.AccessKeyID)) {
			t.Fatal("withdrawn credential present in IAM")
		}
	}
	// Simulate losing a delivery Secret after the new IAM was published. Retry
	// must recover the same active key from IAM.
	if err := store.api.Delete(t.Context(), contracts.RemoteObjectStoreSecret(p.Name, "regional-history", "us"), meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := store.objectStore(t.Context(), p, ids, admin); err != nil {
		t.Fatal(err)
	}
	if writer != credential("eu", "regional-write") || history != credential("eu", "regional-history") || newWriter != credential("us", "regional-write") || newHistory != credential("us", "regional-history") {
		t.Fatal("continuous registration or retry changed active credentials")
	}
	bucket := p.Name + "-evidence"
	var policies map[string]json.RawMessage
	if err := json.Unmarshal(data(p.ObjectStore.IAMSecretName(), SeaweedBucketPoliciesKey), &policies); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"Bucket": bucket, "BucketPolicy": string(policies[bucket]), "Root": root, "Cluster": writer.Principal.ScopeID, "OtherCluster": oldWriter.Principal.ScopeID, "Admin": admin, "Writer": writer, "History": history, "OtherWriter": oldWriter, "OtherHistory": oldHistory, "ReplacementWriter": newWriter, "ReplacementHistory": newHistory})
	if err != nil {
		t.Fatal(err)
	}
	write("fixture.json", raw, 0600)
}
