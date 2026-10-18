package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func readCaptureCleanupInputs(ctx context.Context, files *os.Root, worker contracts.HubWorkerDeployment, claim contracts.CaptureCleanupProjectionClaim) (contracts.CaptureCleanupDeployment, contracts.CaptureCleanupCredentialManifest, error) {
	var c contracts.CaptureCleanupDeployment
	var m contracts.CaptureCleanupCredentialManifest
	fail := func() (contracts.CaptureCleanupDeployment, contracts.CaptureCleanupCredentialManifest, error) {
		return contracts.CaptureCleanupDeployment{}, contracts.CaptureCleanupCredentialManifest{}, mounts.ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil || files == nil || claim.Receipt == nil || worker.Activation == nil || validateHubWorkerInputs(worker) != nil {
		return fail()
	}
	b, err := mounts.Read(ctx, files, contracts.HubWorkerCleanupDeploymentFile, contracts.CaptureCleanupDeploymentMaxBytes)
	if err != nil {
		return fail()
	}
	c, err = contracts.DecodeCaptureCleanupDeployment(bytes.NewReader(b))
	clear(b)
	if err != nil || c.Format != contracts.CaptureCleanupDeploymentFormat || c.InstallationID != worker.InstallationID || !authorization.UUID(c.RootID) || !authorization.UUID(c.StoreID) ||
		c.RoleRootUID != claim.Setup.RoleRootUID || c.RoleSetupID != claim.Setup.RoleSetupID || c.RootID != claim.Setup.PermissionRootID || c.Postgres.MaxConnections != 1 ||
		providerconfig.Validate(worker.Kubernetes, c.Postgres, c.AuditStore, c.KeyService, time.Now()) != nil {
		return fail()
	}
	sign := c.Signing
	if !ownerProviderName.MatchString(sign.Mount) || !ownerProviderName.MatchString(sign.Name) || sign.Version < 1 || sign.Version > 2147483647 || !identity.Text(sign.KeyID, 128) || len(sign.PublicKeys) < 1 || len(sign.PublicKeys) > 16 || len(sign.PublicKeys[sign.KeyID]) != ed25519.PublicKeySize {
		return fail()
	}
	for name, key := range sign.PublicKeys {
		if !identity.Text(name, 128) || len(key) != ed25519.PublicKeySize {
			return fail()
		}
	}
	b, err = mounts.Read(ctx, files, contracts.HubWorkerCleanupManifestFile, contracts.PublicRuntimeCredentialManifestMaxBytes)
	if err != nil {
		return fail()
	}
	m, err = contracts.DecodeCaptureCleanupCredentialManifest(bytes.NewReader(b))
	clear(b)
	if err != nil || postgres.ValidateCaptureCleanupCredentialManifest(m, time.Now()) != nil || m.Input.InstallationID != worker.InstallationID || m.Input.ClusterID != worker.ClusterID || m.Input.Namespace != worker.Namespace ||
		m.Input.OwnerConfigurationUID != worker.OwnerSource.UID || m.RootUID != c.RoleRootUID || m.SetupID != c.RoleSetupID || m.CaptureSetup != claim.Setup ||
		m.Input.Worker.Resources != worker.Activation.Resources || m.Input.Worker.ResourceSetupID != worker.Activation.SetupID || m.Input.Worker.ResourceBinding != worker.Activation.BindingDigest || m.Input.Worker.WorkerLayout != worker.Activation.WorkerLayout ||
		m.Input.Worker.Deployment.Reference != worker.Activation.Deployment || m.Input.Worker.Account.Reference != worker.Activation.ServiceAccount || m.Input.Worker.Lease.Reference != worker.LeaderLease {
		return fail()
	}
	digest, err := contracts.CaptureCleanupProjectionDigest(c, m)
	if err != nil || digest != claim.PublicDigest || ctx.Err() != nil {
		return fail()
	}
	return c, m, nil
}

// Two closed filenames give cleanup and independent verification distinct
// storage credentials. Tokens/credentials rotate only through their protected
// mounted source; a read error cannot fall back to cached private material.
type captureCleanupStorage struct {
	inputs   *providerInputs
	verifier bool
}

func (s captureCleanupStorage) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	name := "cleanup-storage.json"
	if s.verifier {
		name = "verify-storage.json"
	}
	b, err := s.inputs.read(ctx, name, 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 8192) || len(c.SessionToken) > 8192 {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "protected-capture-cleanup"}, nil
}
