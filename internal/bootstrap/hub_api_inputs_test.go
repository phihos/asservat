package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

type fakeHubAPIResolver struct {
	fail  string
	reads []string
}

func (r *fakeHubAPIResolver) step(name string) error {
	r.reads = append(r.reads, name)
	if r.fail == name {
		return errors.New("synthetic failure")
	}
	return nil
}
func (r *fakeHubAPIResolver) NamespaceUID(_ context.Context, name string) (string, error) {
	if name == "hub" {
		return runtimeID, r.step("namespace/" + name)
	}
	return workerNamespaceUIDFixture, r.step("namespace/" + name)
}
func (r *fakeHubAPIResolver) ObjectUID(_ context.Context, _, resource, namespace, name string) (string, error) {
	return "22222222-2222-4222-8222-222222222222", r.step(resource + "/" + namespace + "/" + name)
}
func (r *fakeHubAPIResolver) PKIRoots(_ context.Context, mount string) ([][]byte, error) {
	return hubAPICAFixture, r.step("pki/" + mount)
}
func (r *fakeHubAPIResolver) SigningKey(_ context.Context, role, mount, name string) (int, ed25519.PublicKey, error) {
	if !strings.HasSuffix(role, "-work-sign") {
		return 0, nil, errors.New("not the work-sign role")
	}
	return 3, make(ed25519.PublicKey, ed25519.PublicKeySize), r.step("signing/" + mount + "/" + name)
}
func (r *fakeHubAPIResolver) CapacityPin(_ context.Context, root, installation string) (postgres.CapacityQualificationPin, error) {
	p := audit.OperationLifecyclePolicy{RootID: root, Lane: "capture", InstallationID: installation, StoreID: runtimeID, PolicyID: runtimeID, BackupProfileID: runtimeID, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 1, BackupReservedBytes: 1<<63 - 1, WALReservedBytes: 1<<63 - 1, MaxPurgeLeases: 8, CleanupBudgetSeconds: 15, ProofWindowSeconds: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), History: &audit.OperationHistoryQualification{ID: runtimeID, Digest: artifact.Digest{3}, Layout: audit.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 256 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 2}}
	raw, _ := json.Marshal(p)
	return postgres.CapacityQualificationPin{QualificationID: runtimeID, QualificationDigest: strings.Repeat("ab", 32), AccountVersion: runtimeID + "-account/v1", CapturePolicy: raw, OperationRetentionSeconds: 10000}, r.step("capacity")
}

const workerNamespaceUIDFixture = "33333333-3333-4333-8333-333333333333"

var hubAPICAFixture [][]byte

func hubAPIConfigFixture() contracts.HubAPIConfig {
	return contracts.HubAPIConfig{Format: contracts.HubAPIConfigFormat, Namespace: "hub", Deployment: "asservat-hub-api", ServiceAccount: "asservat-hub-api", OwnerConfiguration: "asservat-owner-source", AuditCredentials: "asservat-s3-hub-api", ProviderAuthMount: "asservat-owner",
		Postgres:    contracts.HubAPIPostgres{Host: "asservat-postgres.hub.svc", Port: 5432, Database: "asservat", MaxConnections: 1},
		AuditStore:  contracts.HubAPIAuditStore{Endpoint: "https://asservat-objectstore.hub.svc:8333", Region: "us-east-1", Bucket: "asservat-audit"},
		KeyService:  contracts.HubAPIKeyService{Endpoint: "https://asservat-openbao.hub.svc:8200", AuditMount: "asservat-audit", AuditKey: "audit", PKIMount: "owner-pki", ServerRole: "asservat-owner-server", ClientRole: "asservat-owner-client"},
		Connections: 4, Concurrency: 2,
		Observation: contracts.HubAPIObservation{LocalCapacity: &contracts.HubAPILocalCapacity{Keys: []string{"asservat-trial"}, CallerAccount: "asservat-hub-worker", CallerDeployment: "asservat-hub-worker"}},
		Native:      contracts.HubAPINative{ConnectorPKIMount: "connector-pki", WorkerAPIs: []contracts.HubAPIWorkerAPI{{Namespace: "asservat-downloads"}}, RetentionTopologies: []contracts.HubAPITopology{}, Connections: 4, Concurrency: 2},
		Public: &contracts.HubAPIPublic{Origin: "https://asservat.example.test", BrowserAudience: "asservat-api", BrowserSettings: "asservat-browser-settings", IdentitySettings: "asservat-identity-settings",
			SessionTransit: contracts.OwnerPublicTransit{Mount: "public-transit", Key: "asservat-browser-sessions"}, ClusterCatalog: "asservat-cluster-catalog",
			WorkSigning: contracts.HubAPISigning{Mount: "public-transit", Name: "asservat-work-signing"}, WorkerConfiguration: "asservat-worker-profile",
			WorkerPKI: contracts.HubAPIWorkerPKI{Mount: "worker-pki", Role: "asservat-download-worker"}, DownloadEnvironment: "asservat-download-environment", ArtifactKeyID: "asservat-artifact",
			Standby: 2, Captures: 1, PreviewSeconds: 120, DownloadPlan: contracts.OwnerPublicDownloadPlan{OutputLimit: 1 << 28, ReadLimit: 1 << 28, RequestLimit: 4, DurationSeconds: 300},
			ProxyTLS: true, Port: contracts.OwnerInstalledPublicPort, Version: "test", OperationConcurrency: 8, MCPPerIdentity: 2, DownloadConcurrency: 4, DownloadsPerIdentity: 2, DownloadMaxSeconds: 3600,
			OperationAudit: contracts.OwnerPublicOperationAudit{NormalConcurrency: 8, ResolutionConcurrency: 2, PerPrincipalConcurrency: 2, NormalPerSecond: 50, ResolutionPerSecond: 10}}}
}

// hubAPIFiles writes the CA files of the credential root.
func hubAPIFiles(t *testing.T, skip string) *os.Root {
	t.Helper()
	f, _, l := newRuntimeFixture(t)
	l.Close()
	hubAPICAFixture = [][]byte{f.ca.Raw}
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})
	for _, name := range []string{contracts.HubAPIKubernetesCAFile, contracts.HubAPIPostgresCAFile, contracts.HubAPIAuditStoreCAFile, contracts.HubAPIKeyServiceCAFile, contracts.HubAPIIdentityCAFile} {
		if name == skip {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), ca, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func hubAPIIDsRoot(t *testing.T, skip string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"installationID", "clusterID", "issuerEpoch", "permissionRootID", "browserRootID", "sessionEpoch", "roleSetupID", "peerID"} {
		if key == skip {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, key), []byte(runtimeID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestHubAPIInputsMergeConfigIDsAndStartupReads(t *testing.T) {
	ctx := context.Background()
	files := hubAPIFiles(t, "")
	ids, err := readHubAPIIDs(ctx, hubAPIIDsRoot(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeHubAPIResolver{}
	c, err := buildHubAPIDeployment(ctx, files, hubAPIConfigFixture(), ids, r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.InstallationID != runtimeID || c.Namespace != (contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}) || c.ConfigurationUID == "" || c.ProviderAuthentication == nil || c.ProviderAuthentication.ServiceAccount.UID != "" || c.ProviderAuthentication.RecipeSHA256 == "" {
		t.Fatal("identity fields", c.InstallationID, c.Namespace, c.ProviderAuthentication)
	}
	if c.WorkloadGuard.PolicyUID != "" || c.Observation == nil || c.Observation.Activation != nil || c.Public.RuntimeProjection != (contracts.WorkerObjectReference{}) {
		t.Fatal("installer pins entered the composed input")
	}
	want := kube.WorkloadProtectionDigest(runtimeID, "hub", "asservat-hub-api")
	if c.Observation.ProtectionDigest != hubAPIDigestHex(want) || len(c.Observation.Peers) != 1 || c.Observation.Peers[0].PeerID != runtimeID {
		t.Fatal("observation pin or local peer", c.Observation)
	}
	l := c.Observation.LocalCapacity
	if l == nil || l.ProbeNamespace != c.Namespace || l.Caller.AccountUID == "" || l.Caller.ProtectionDigest != c.Observation.ProtectionDigest {
		t.Fatal("local capacity caller", l)
	}
	if n := c.Native; n == nil || len(n.WorkerAPIs) != 1 || n.WorkerAPIs[0].Namespace.UID != workerNamespaceUIDFixture || len(n.ConnectorRoots) != 1 {
		t.Fatal("native worker APIs", c.Native)
	}
	p := c.Public
	if p.WorkSigning.Version != 3 || p.WorkSigning.KeyID != "asservat-work-signing-v3" || p.AuditStoreID != runtimeID || p.OperationAudit.RetentionSeconds != 10000 || p.Capacity.QualificationID != runtimeID || !p.ProxyTLS || p.ProviderRecipeSHA256 == "" || p.WorkerPKI.IssuerEpoch != runtimeID || len(p.WorkerPKI.Roots) != 1 {
		t.Fatal("public J values", p.WorkSigning, p.AuditStoreID, p.Capacity)
	}
	// The worker profile is read in the download-worker namespace.
	found := false
	for _, read := range r.reads {
		found = found || read == "configmaps/asservat-downloads/asservat-worker-profile"
	}
	if !found {
		t.Fatal("worker profile not read in the worker namespace", r.reads)
	}
}

func TestHubAPIInputsNameTheMissingInput(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mutate       func(*contracts.HubAPIConfig)
		skipCA, fail string
		want         string
	}{
		"namespace":           {mutate: func(c *contracts.HubAPIConfig) { c.Namespace = "" }, want: "input-namespace"},
		"owner-config":        {mutate: func(c *contracts.HubAPIConfig) { c.OwnerConfiguration = "" }, want: "input-ownerConfiguration"},
		"postgres-ca":         {skipCA: contracts.HubAPIPostgresCAFile, want: "input-ca-postgres-ca.crt"},
		"identity-ca":         {skipCA: contracts.HubAPIIdentityCAFile, want: "input-ca-identity-ca.crt"},
		"namespace-uid":       {fail: "namespace/hub", want: "input-namespace-uid"},
		"capacity":            {fail: "capacity", want: "input-capacity-qualification"},
		"connector-roots":     {fail: "pki/connector-pki", want: "input-connector-roots"},
		"work-signing":        {fail: "signing/public-transit/asservat-work-signing", want: "input-work-signing-key"},
		"invalid-composition": {mutate: func(c *contracts.HubAPIConfig) { c.Connections = 0 }, want: "identity"},
	} {
		t.Run(name, func(t *testing.T) {
			c := hubAPIConfigFixture()
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			ids, _ := readHubAPIIDs(ctx, hubAPIIDsRoot(t, ""))
			_, err := buildHubAPIDeployment(ctx, hubAPIFiles(t, tc.skipCA), c, ids, &fakeHubAPIResolver{fail: tc.fail}, time.Now())
			var step interface{ FixedStep() string }
			if err == nil || !errors.As(err, &step) || step.FixedStep() != tc.want {
				t.Fatal("refusal", err)
			}
		})
	}
	if _, err := readHubAPIIDs(ctx, hubAPIIDsRoot(t, "peerID")); err == nil || err.Error() != "hub-api input ids-peerID" {
		t.Fatal("missing ID", err)
	}
}

func TestHubAPIConfigDecodeIsClosed(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, _ := json.Marshal(hubAPIConfigFixture())
	if err = os.WriteFile(filepath.Join(dir, contracts.HubAPIConfigFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := readHubAPIConfig(context.Background(), root); err != nil || c.Public == nil || c.Public.Origin != "https://asservat.example.test" {
		t.Fatal("config", err)
	}
	unknown := strings.Replace(string(raw), `"format"`, `"workloadGuard":{},"format"`, 1)
	if err = os.WriteFile(filepath.Join(dir, contracts.HubAPIConfigFile), []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHubAPIConfig(context.Background(), root); err == nil {
		t.Fatal("unknown installer field accepted")
	}
}

func hubAPIDigestHex(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
