package providerconfig

import (
	"encoding/json"
	"reflect"
	"slices"

	"asservat.local/asservat/internal/contracts"
)

// AppendSeaweedRegionalGrants appends only independently selected regional
// grants to the original pinned private IAM source. Retained identities are
// preserved, not interpreted as new authority. Trusted provider administration
// is serialized by the installation profile; this is not a concurrent merger.
// Policies contains only the new grants' statements, for AppendBucketPolicy.
func AppendSeaweedRegionalGrants(original []byte, admin contracts.SeaweedCredential, installationID string, grants []contracts.SeaweedGrant) (CompiledSeaweedStorage, error) {
	zero := CompiledSeaweedStorage{}
	if len(grants) < 1 || len(grants) > 2 {
		return zero, ErrSeaweedStorage
	}
	cluster, bucket := grants[0].ClusterID, grants[0].Bucket
	for _, g := range grants {
		if (g.Credential.Principal.Purpose != "regional-write" && g.Credential.Principal.Purpose != "regional-history") || g.InstallationID != installationID || g.ClusterID != cluster || g.Bucket != bucket {
			return zero, ErrSeaweedStorage
		}
	}
	additions, err := CompileSeaweedStorage(admin, grants)
	if err != nil {
		return zero, err
	}
	defer clear(additions.Config)
	retained, err := decodeSeaweedIdentities(original)
	if err != nil {
		return zero, err
	}
	next, err := decodeSeaweedIdentities(additions.Config)
	if err != nil {
		return zero, err
	}
	adminName, _ := SeaweedPrincipalName(admin.Principal)
	if !reflect.DeepEqual(retained[adminName], next[adminName]) {
		return zero, ErrSeaweedStorage
	}
	// Prove the selected installation against its fixed original principal;
	// unrelated retained runtime identities remain opaque and unchanged.
	initial, err := ReadSeaweedInitialAuditCredential(original, installationID)
	if err != nil {
		return zero, err
	}
	initialConfig, err := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{{Credential: initial, Bucket: bucket, InstallationID: installationID}})
	if err != nil {
		return zero, err
	}
	defer clear(initialConfig.Config)
	expected, err := decodeSeaweedIdentities(initialConfig.Config)
	if err != nil {
		return zero, err
	}
	initialName, _ := SeaweedPrincipalName(initial.Principal)
	if !reflect.DeepEqual(retained[initialName], expected[initialName]) {
		return zero, ErrSeaweedStorage
	}
	for name, identity := range next {
		if previous, exists := retained[name]; exists {
			if !reflect.DeepEqual(previous, identity) {
				return zero, ErrSeaweedStorage
			}
		} else {
			retained[name] = identity
		}
	}
	names := make([]string, 0, len(retained)-1)
	for name := range retained {
		if name != adminName {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	identities := []seaweedIdentity{retained[adminName]}
	for _, name := range names {
		identities = append(identities, retained[name])
	}
	raw, err := json.Marshal(struct {
		Identities []seaweedIdentity `json:"identities"`
	}{identities})
	if err != nil || ValidateSeaweedConfigTransition(original, raw) != nil {
		clear(raw)
		return zero, ErrSeaweedStorage
	}
	return CompiledSeaweedStorage{Config: raw, Policies: additions.Policies}, nil
}
