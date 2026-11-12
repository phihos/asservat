package providerconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func regionalAppendFixture(t *testing.T) (contracts.SeaweedCredential, CompiledSeaweedStorage, []contracts.SeaweedGrant) {
	t.Helper()
	admin := swCredential(t, "admin", swRoot)
	retained := []contracts.SeaweedGrant{
		{Credential: swCredential(t, "initial-audit", swInstall), Bucket: "audit", InstallationID: swInstall},
		{Credential: swCredential(t, "owner-audit", swInstall), Bucket: "audit", InstallationID: swInstall, RootID: swRoot, Prefixes: []string{"operation-audit/v1/" + swRoot + "/"}},
		{Credential: swCredential(t, "operation-cleanup", swInstall), Bucket: "audit", InstallationID: swInstall, RootID: swRoot},
	}
	original, err := CompileSeaweedStorage(admin, retained)
	if err != nil {
		t.Fatal(err)
	}
	grants := []contracts.SeaweedGrant{
		{Credential: swCredential(t, "regional-write", swCluster), Bucket: "audit", InstallationID: swInstall, ClusterID: swCluster},
		{Credential: swCredential(t, "regional-history", swCluster), Bucket: "audit", InstallationID: swInstall, ClusterID: swCluster, RootID: swRoot},
	}
	return admin, original, grants
}
func TestSeaweedRegionalAppendPreservesAllRetainedPrincipalsAndReplays(t *testing.T) {
	admin, original, grants := regionalAppendFixture(t)
	defer clear(original.Config)
	before := bytes.Clone(original.Config)
	defer clear(before)
	next, err := AppendSeaweedRegionalGrants(original.Config, admin, swInstall, grants)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(next.Config)
	oldIDs, _ := decodeSeaweedIdentities(original.Config)
	newIDs, _ := decodeSeaweedIdentities(next.Config)
	if len(newIDs) != len(oldIDs)+2 {
		t.Fatal("wrong principal count")
	}
	for name, identity := range oldIDs {
		if !reflect.DeepEqual(identity, newIDs[name]) {
			t.Fatal("retained principal changed")
		}
	}
	if !bytes.Equal(before, original.Config) || ValidateSeaweedConfigTransition(original.Config, next.Config) != nil {
		t.Fatal("original source mutated or dropped")
	}
	var policy seaweedPolicy
	if json.Unmarshal(next.Policies["audit"], &policy) != nil || len(policy.Statement) != 7 {
		t.Fatal("policy must contain only compiled regional additions")
	}
	replay, err := AppendSeaweedRegionalGrants(next.Config, admin, swInstall, grants)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(replay.Config)
	if !bytes.Equal(next.Config, replay.Config) || !bytes.Equal(next.Policies["audit"], replay.Policies["audit"]) {
		t.Fatal("exact replay changed retained keys or capabilities")
	}
}
func TestSeaweedRegionalAppendRefusesReplacementAndForeignAuthority(t *testing.T) {
	for _, mode := range []string{"new-key", "new-capability", "changed-retained-admin", "duplicate-key", "other-purpose", "other-installation", "other-cluster", "other-bucket", "changed-existing-history-root", "unknown-field", "empty"} {
		t.Run(mode, func(t *testing.T) {
			admin, original, grants := regionalAppendFixture(t)
			defer clear(original.Config)
			first, err := AppendSeaweedRegionalGrants(original.Config, admin, swInstall, grants)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(first.Config)
			source := first.Config
			switch mode {
			case "new-key":
				grants[0].Credential = swCredential(t, "regional-write", swCluster)
			case "new-capability":
				var d struct {
					Identities []seaweedIdentity `json:"identities"`
				}
				_ = json.Unmarshal(source, &d)
				for i := range d.Identities {
					if d.Identities[i].Name == "asservat-regional-write-"+swCluster {
						d.Identities[i].Actions = append(d.Identities[i].Actions, "Read:audit/v1/"+swCluster+"/*")
					}
				}
				source, _ = json.Marshal(d)
				defer clear(source)
			case "changed-retained-admin":
				admin = swCredential(t, "admin", swRoot)
			case "duplicate-key":
				grants[0].Credential.AccessKeyID = admin.AccessKeyID
			case "other-purpose":
				grants[0].Credential = swCredential(t, "download-read", swInstall)
			case "other-installation":
				grants[0].InstallationID = swRoot
			case "other-cluster":
				grants[1].ClusterID = swRoot
			case "other-bucket":
				grants[1].Bucket = "other"
			case "changed-existing-history-root":
				grants[1].RootID = swInstall
			case "unknown-field":
				source = bytes.Replace(source, []byte(`"identities":`), []byte(`"unknown":`), 1)
				defer clear(source)
			case "empty":
				grants = nil
			}
			if result, err := AppendSeaweedRegionalGrants(source, admin, swInstall, grants); err == nil {
				clear(result.Config)
				t.Fatal("changed/foreign regional append accepted")
			}
		})
	}
}
