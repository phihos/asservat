package bootstrap

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/google/uuid"
)

func ownerSeaweedFixture(t *testing.T, full bool) (continuationSeaweedOwnerInput, contracts.SeaweedCredential, contracts.SeaweedGrant) {
	t.Helper()
	_, _, owner := ownerProviderInputFixture(t)
	profile := *owner.ProviderAuthentication
	now := time.Now()
	pool := fleet.OwnerPool{InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, IssuerEpoch: uuid.NewString(), Namespace: owner.Namespace.Name, NamespaceUID: owner.Namespace.UID, Service: "hub", ServiceUID: uuid.NewString(), Deployment: "hub", DeploymentUID: uuid.NewString(), ServiceAccount: profile.ServiceAccount.Name, AccountUID: profile.ServiceAccount.UID, Port: 8443, NativePort: 9444, NativeBootstrap: fleet.OwnerBootstrapProfile}
	credential := func(purpose string) contracts.SeaweedCredential {
		c, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: owner.InstallationID})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	roles, _, worker := configurationRoleInputPair(t)
	worker.InstallationID, worker.ClusterID, worker.Namespace, worker.AuditStore = owner.InstallationID, owner.ClusterID, owner.Namespace, owner.AuditStore
	account := roles.Roles.ServiceAccount
	account.Name = "asservat-" + strings.ReplaceAll(owner.InstallationID, "-", "") + "-worker"
	selection := contracts.ConfigurationProviderSelection{AuthMount: "worker-auth", AuthMountAccessor: "auth_worker_original", AuditCredentials: contracts.WorkerObjectReference{Name: "asservat-" + strings.ReplaceAll(owner.InstallationID, "-", "") + "-worker-providers", UID: uuid.NewString()}}
	workerGrant, err := workerSeaweedGrant(worker, selection, account, contracts.HubWorkerProviderInstalledLayout, credential("configuration-audit"), now)
	if err != nil {
		t.Fatal("actual worker recipe", err)
	}
	in := continuationSeaweedOwnerInput{Store: owner.AuditStore, Owner: owner, Profile: profile, Worker: workerGrant, Credentials: continuationSeaweedOwnerCredentials{Owner: credential("owner-audit")}, Now: now}
	if full {
		owner.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "public-transit", Name: "work"}, WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker", IssuerEpoch: pool.IssuerEpoch}}
		in.Owner = owner
		f := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, PermissionRootID: owner.PermissionRootID, AuditStore: owner.AuditStore, KeyService: contracts.FederationKeyService{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, AuditMount: owner.KeyService.AuditMount, AuditKey: "federation-audit", PKIMount: "connector-pki", ClientRole: "connector-client", ServerRole: "connector-server"}}
		fr, e := providerconfig.FederationProviderRecipeFor(f, contracts.FederationProviderAuthentication{AuthMount: profile.AuthMount, AuthMountAccessor: profile.AuthMountAccessor, Namespace: owner.Namespace, ServiceAccount: contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(owner.InstallationID), UID: uuid.NewString()}, AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: uuid.NewString()}})
		if e != nil {
			t.Fatal(e)
		}
		f.ProviderAuthentication = &fr.Profile
		in.Federation = &f
		p := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, PermissionRootID: owner.PermissionRootID, Namespace: owner.Namespace, AuditStore: owner.AuditStore, AuditKeys: contracts.PublisherTransit{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, Mount: owner.KeyService.AuditMount, Key: providerconfig.PublisherAuditKey(owner.InstallationID)}, Verifier: contracts.PublisherVerifier{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, PKIMount: owner.Public.WorkerPKI.Mount, Role: contracts.PublisherVerifierRole(owner.InstallationID)}, Evidence: contracts.PublisherEvidence{Endpoint: owner.AuditStore.Endpoint, Roots: owner.AuditStore.Roots, Region: owner.AuditStore.Region, Bucket: owner.AuditStore.Bucket}}
		pr, e := providerconfig.PublisherProviderRecipeFor(p, contracts.PublisherProviderAuthentication{AuthMount: profile.AuthMount, AuthMountAccessor: profile.AuthMountAccessor, Namespace: owner.Namespace, ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(owner.InstallationID), UID: uuid.NewString()}})
		if e != nil {
			t.Fatal(e)
		}
		p.ProviderAuthentication = pr.Profile
		in.Publisher = &p
		var roots bytes.Buffer
		for _, r := range owner.AuditStore.Roots {
			if pem.Encode(&roots, &pem.Block{Type: "CERTIFICATE", Bytes: r}) != nil {
				t.Fatal("roots")
			}
		}
		evidence := contracts.InstallerEvidenceStore{Endpoint: owner.AuditStore.Endpoint, RootsPEM: roots.String(), Region: owner.AuditStore.Region, Bucket: owner.AuditStore.Bucket}
		in.Downloads, in.Deletion, in.Cleanup = &evidence, &evidence, true
		in.Credentials.Federation = credential("federation-audit")
		in.Credentials.PublisherAudit = credential("publisher-audit")
		in.Credentials.PublisherRead = credential("publisher-read")
		in.Credentials.DownloadRead = credential("download-read")
		in.Credentials.EvidenceDelete = credential("evidence-delete")
		in.Credentials.Cleanup = credential("operation-cleanup")
		in.Credentials.Verify = credential("operation-verify")
	}
	in.Artifact, err = providerconfig.OwnerProviderSetupArtifact(in.Owner, profile, pool, owner.KeyService.Roots, now, in.Federation, in.Publisher, in.Downloads, in.Deletion, in.Cleanup)
	if err != nil {
		t.Fatal("actual phase3 recipe", err)
	}
	admin, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: uuid.NewString()})
	if e != nil {
		t.Fatal(e)
	}
	initial := contracts.SeaweedGrant{Credential: credential("initial-audit"), Bucket: in.Store.Bucket, InstallationID: owner.InstallationID}
	return in, admin, initial
}
func compileOwnerSeaweedFixture(in continuationSeaweedOwnerInput, admin contracts.SeaweedCredential, initial contracts.SeaweedGrant) (providerconfig.CompiledSeaweedStorage, []contracts.SeaweedGrant, error) {
	grants, err := ownerSeaweedGrants(in)
	if err != nil {
		return providerconfig.CompiledSeaweedStorage{}, nil, err
	}
	compiled, err := providerconfig.CompileSeaweedStorage(admin, append([]contracts.SeaweedGrant{initial}, grants...))
	return compiled, grants, err
}
func TestOwnerSeaweedGrantsCompileActualCompleteRecipeAndReplay(t *testing.T) {
	for _, full := range []bool{false, true} {
		in, admin, initial := ownerSeaweedFixture(t, full)
		compiled, grants, err := compileOwnerSeaweedFixture(in, admin, initial)
		if err != nil {
			t.Fatal("actual recipe refused", err)
		}
		defer clear(compiled.Config)
		expected := 3
		if full {
			expected = 10
		}
		if len(grants)+1 != expected || !reflect.DeepEqual(grants[0], in.Worker) {
			t.Fatal("initial/worker integration duplicated or lost")
		}
		purposes := map[string]contracts.SeaweedGrant{}
		for _, g := range grants {
			purposes[g.Credential.Principal.Purpose] = g
			if g.InstallationID != in.Owner.InstallationID || g.Bucket != in.Store.Bucket {
				t.Fatal("foreign grant")
			}
		}
		var artifact struct {
			AuditStorage struct {
				Prefixes []string `json:"prefixes"`
			} `json:"auditStorage"`
		}
		if json.Unmarshal(in.Artifact, &artifact) != nil || !slices.Equal(purposes["owner-audit"].Prefixes, artifact.AuditStorage.Prefixes) {
			t.Fatal("owner prefixes differ from recipe")
		}
		if full && (!slices.Equal(purposes["publisher-audit"].Prefixes, []string{"context-verification/v1/" + in.Owner.PermissionRootID + "/"}) || purposes["operation-cleanup"].RootID != in.Owner.PermissionRootID || len(purposes) != 9) {
			t.Fatal("complete phase3 scopes lost")
		}
		again, _, err := compileOwnerSeaweedFixture(in, admin, initial)
		if err != nil || !bytes.Equal(compiled.Config, again.Config) || !reflect.DeepEqual(compiled.Policies, again.Policies) || providerconfig.ValidateSeaweedConfigTransition(compiled.Config, again.Config) != nil {
			t.Fatal("stable exact replay changed IAM")
		}
		clear(again.Config)
		var iam struct {
			Identities []json.RawMessage `json:"identities"`
		}
		if json.Unmarshal(compiled.Config, &iam) != nil || len(iam.Identities) != expected+1 || len(compiled.Policies) != 1 {
			t.Fatal("wrong IAM identity/bucket count")
		}
	}
}
func TestOwnerSeaweedGrantsRefuseForeignScopeAndOptionalMaterial(t *testing.T) {
	for _, mode := range []string{"store-endpoint", "store-ca", "store-region", "store-bucket", "worker-installation", "worker-scope", "owner-key", "federation-ca", "publisher-ca", "download-ca", "deletion-bucket", "missing-cleanup-key", "extra-optional-key", "wrong-configuration", "owner-secret", "foreign-prefix", "missing-section"} {
		t.Run(mode, func(t *testing.T) {
			in, admin, initial := ownerSeaweedFixture(t, true)
			switch mode {
			case "store-endpoint":
				in.Store.Endpoint = "https://foreign.invalid"
			case "store-ca":
				in.Store.Roots = [][]byte{{1}}
			case "store-region":
				in.Store.Region = "foreign"
			case "store-bucket":
				in.Store.Bucket = "foreign"
			case "worker-installation":
				in.Worker.InstallationID = uuid.NewString()
			case "worker-scope":
				in.Worker.Credential.Principal.Purpose = "owner-audit"
			case "owner-key":
				in.Credentials.Owner.Principal.ScopeID = uuid.NewString()
			case "federation-ca":
				f := *in.Federation
				f.AuditStore.Roots = [][]byte{{1}}
				in.Federation = &f
			case "publisher-ca":
				p := *in.Publisher
				p.Evidence.Roots = [][]byte{{1}}
				in.Publisher = &p
			case "download-ca":
				e := *in.Downloads
				e.RootsPEM = "invalid"
				in.Downloads = &e
			case "deletion-bucket":
				e := *in.Deletion
				e.Bucket = "foreign"
				in.Deletion = &e
			case "missing-cleanup-key":
				in.Credentials.Cleanup = contracts.SeaweedCredential{}
			case "extra-optional-key":
				in.Downloads = nil
			case "wrong-configuration":
				in.Owner.ConfigurationUID = uuid.NewString()
			case "owner-secret", "foreign-prefix", "missing-section":
				var doc map[string]any
				if json.Unmarshal(in.Artifact, &doc) != nil {
					t.Fatal("artifact")
				}
				switch mode {
				case "owner-secret":
					doc["auditStorage"].(map[string]any)["secretKey"] = "foreign.json"
				case "foreign-prefix":
					doc["auditStorage"].(map[string]any)["prefixes"] = []string{"foreign/"}
				case "missing-section":
					delete(doc, "operationCleanupStorage")
				}
				in.Artifact, _ = json.Marshal(doc)
			}
			compiled, _, err := compileOwnerSeaweedFixture(in, admin, initial)
			clear(compiled.Config)
			if err == nil {
				t.Fatal("foreign/incomplete phase3 set accepted")
			}
		})
	}
}
