package bootstrap

import (
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Every value comes from the protected original continuation and stable key
// carriers. This pure compiler neither reads IAM as authority nor generates keys.
type continuationSeaweedOwnerCredentials struct {
	Owner, Federation, PublisherAudit, PublisherRead contracts.SeaweedCredential
	DownloadRead, EvidenceDelete, Cleanup, Verify    contracts.SeaweedCredential
}
type continuationSeaweedOwnerInput struct {
	Store               contracts.OwnerAuditStore
	Owner               contracts.OwnerDeployment
	Profile             contracts.OwnerProviderAuthentication
	Artifact            []byte
	Worker              contracts.SeaweedGrant
	Credentials         continuationSeaweedOwnerCredentials
	Federation          *contracts.FederationDeployment
	Publisher           *contracts.PublisherDeployment
	Downloads, Deletion *contracts.InstallerEvidenceStore
	Cleanup             bool
	Now                 time.Time
}
type seaweedOwnerAuditStorage struct {
	Store       contracts.OwnerAuditStore       `json:"store"`
	Credentials contracts.WorkerObjectReference `json:"credentials"`
	SecretKey   string                          `json:"secretKey"`
	Prefixes    []string                        `json:"prefixes"`
}
type seaweedOwnerObjectStorage struct {
	Endpoint  string   `json:"endpoint"`
	Region    string   `json:"region"`
	Bucket    string   `json:"bucket"`
	SecretKey string   `json:"secretKey"`
	Prefixes  []string `json:"prefixes"`
}

// ownerSeaweedGrants returns only the retained worker and phase-3 grants. The
// existing enable path prepends its separately pinned original initial-audit
// credential exactly once and compiles the complete set, refusing unknown or
// dropped retained principals. Storage prefixes come from the actual artifact.
func ownerSeaweedGrants(in continuationSeaweedOwnerInput) ([]contracts.SeaweedGrant, error) {
	fail := func() ([]contracts.SeaweedGrant, error) { return nil, mounts.ErrUnavailable }
	if in.Now.IsZero() || providerconfig.ValidateOwnerProviderAuthentication(in.Owner, in.Profile, in.Now) != nil || !reflect.DeepEqual(in.Store, in.Owner.AuditStore) {
		return fail()
	}
	installation, cluster, root := in.Owner.InstallationID, in.Owner.ClusterID, in.Owner.PermissionRootID
	worker := in.Worker
	if worker.InstallationID != installation || worker.ClusterID != cluster || worker.Bucket != in.Store.Bucket || worker.Credential.Principal != (contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: installation}) {
		return fail()
	}
	var artifact struct {
		Format            string                    `json:"format"`
		ConfigurationUID  string                    `json:"configurationUID"`
		Public            bool                      `json:"public"`
		AuditStorage      seaweedOwnerAuditStorage  `json:"auditStorage"`
		Federation        bool                      `json:"federation"`
		FederationStorage *seaweedOwnerAuditStorage `json:"federationAuditStorage"`
		Publisher         *struct {
			AuditStorage    seaweedOwnerObjectStorage `json:"auditStorage"`
			EvidenceStorage seaweedOwnerObjectStorage `json:"evidenceReadStorage"`
		} `json:"publisher"`
		DownloadStorage *seaweedOwnerObjectStorage                          `json:"downloadEvidenceReadStorage"`
		DeleteStorage   *seaweedOwnerObjectStorage                          `json:"evidenceDeleteStorage"`
		CleanupStorage  *providerconfig.OperationCleanupStorageRequirements `json:"operationCleanupStorage"`
	}
	if len(in.Artifact) == 0 || len(in.Artifact) > 64<<10 || json.Unmarshal(in.Artifact, &artifact) != nil || artifact.Format != "asservat-owner-provider-setup/v1" || artifact.ConfigurationUID != in.Owner.ConfigurationUID || artifact.Public != (in.Owner.Public != nil && in.Owner.Public.SessionTransit.Key != "") || artifact.Federation != (in.Federation != nil) || (artifact.FederationStorage != nil) != (in.Federation != nil) || (artifact.Publisher != nil) != (in.Publisher != nil) || (artifact.DownloadStorage != nil) != (in.Downloads != nil) || (artifact.DeleteStorage != nil) != (in.Deletion != nil) || (artifact.CleanupStorage != nil) != in.Cleanup {
		return fail()
	}
	grants := []contracts.SeaweedGrant{worker}
	grants[0].Prefixes = slices.Clone(worker.Prefixes)
	add := func(purpose string, c contracts.SeaweedCredential, prefixes []string) bool {
		if c.Principal != (contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: installation}) || providerconfig.ValidateSeaweedCredential(c) != nil {
			return false
		}
		grants = append(grants, contracts.SeaweedGrant{Credential: c, Bucket: in.Store.Bucket, InstallationID: installation, ClusterID: cluster, RootID: root, Prefixes: slices.Clone(prefixes)})
		return true
	}
	audit := func(s seaweedOwnerAuditStorage, ref contracts.WorkerObjectReference, file string) bool {
		return reflect.DeepEqual(s.Store, in.Store) && s.Credentials == ref && s.SecretKey == file && len(s.Prefixes) > 0
	}
	objects := func(s seaweedOwnerObjectStorage, file string) bool {
		return s.Endpoint == in.Store.Endpoint && s.Region == in.Store.Region && s.Bucket == in.Store.Bucket && s.SecretKey == file
	}
	evidence := func(e *contracts.InstallerEvidenceStore) bool {
		roots, err := providerconfig.TrustRootsPEM([]byte(e.RootsPEM), in.Now)
		return err == nil && e.Endpoint == in.Store.Endpoint && e.Region == in.Store.Region && e.Bucket == in.Store.Bucket && reflect.DeepEqual(roots, in.Store.Roots)
	}
	if !audit(artifact.AuditStorage, in.Profile.AuditCredentials, contracts.OwnerProviderAuditCredentialFile) || !add("owner-audit", in.Credentials.Owner, artifact.AuditStorage.Prefixes) {
		return fail()
	}
	zero := contracts.SeaweedCredential{}
	if f := in.Federation; f != nil {
		if f.InstallationID != installation || f.ClusterID != cluster || f.PermissionRootID != root || f.ProviderAuthentication == nil || !reflect.DeepEqual(f.AuditStore, in.Store) {
			return fail()
		}
		if _, err := providerconfig.FederationProviderSetupFor(*f); err != nil {
			return fail()
		}
		if !audit(*artifact.FederationStorage, f.ProviderAuthentication.AuditCredentials, contracts.FederationProviderAuditCredentialFile) || !add("federation-audit", in.Credentials.Federation, artifact.FederationStorage.Prefixes) {
			return fail()
		}
	} else if in.Credentials.Federation != zero {
		return fail()
	}
	if p := in.Publisher; p != nil {
		if p.InstallationID != installation || p.ClusterID != cluster || p.PermissionRootID != root || !reflect.DeepEqual(p.AuditStore, in.Store) || p.Evidence.Endpoint != in.Store.Endpoint || p.Evidence.Region != in.Store.Region || p.Evidence.Bucket != in.Store.Bucket || !reflect.DeepEqual(p.Evidence.Roots, in.Store.Roots) {
			return fail()
		}
		if _, err := providerconfig.PublisherProviderSetupFor(*p); err != nil {
			return fail()
		}
		a, e := artifact.Publisher.AuditStorage, artifact.Publisher.EvidenceStorage
		if !objects(a, contracts.PublisherAuditCredential) || len(a.Prefixes) == 0 || !objects(e, contracts.PublisherEvidenceCredential) || len(e.Prefixes) != 0 || !add("publisher-audit", in.Credentials.PublisherAudit, a.Prefixes) || !add("publisher-read", in.Credentials.PublisherRead, nil) {
			return fail()
		}
	} else if in.Credentials.PublisherAudit != zero || in.Credentials.PublisherRead != zero {
		return fail()
	}
	if in.Downloads != nil {
		if !artifact.Public || !evidence(in.Downloads) || !objects(*artifact.DownloadStorage, "credentials.json") || len(artifact.DownloadStorage.Prefixes) != 0 || !add("download-read", in.Credentials.DownloadRead, nil) {
			return fail()
		}
	} else if in.Credentials.DownloadRead != zero {
		return fail()
	}
	if in.Deletion != nil {
		if !artifact.Public || !evidence(in.Deletion) || !objects(*artifact.DeleteStorage, contracts.EvidenceDeleteCredentialFile) || !slices.Equal(artifact.DeleteStorage.Prefixes, []string{"v1/"}) || !add("evidence-delete", in.Credentials.EvidenceDelete, nil) {
			return fail()
		}
	} else if in.Credentials.EvidenceDelete != zero {
		return fail()
	}
	if in.Cleanup {
		if !reflect.DeepEqual(artifact.CleanupStorage, providerconfig.OperationCleanupStorageRequirementsFor(in.Store, root)) || !add("operation-cleanup", in.Credentials.Cleanup, nil) || !add("operation-verify", in.Credentials.Verify, nil) {
			return fail()
		}
	} else if in.Credentials.Cleanup != zero || in.Credentials.Verify != zero {
		return fail()
	}
	// The actual compiler enforces purpose/root/prefix scopes, duplicate keys and
	// finite dimensions too. The caller compiles these with original initial/admin.
	return grants, nil
}
