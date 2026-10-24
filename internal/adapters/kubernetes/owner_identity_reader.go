package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// InstalledOwnerIdentityReader checks native original installation provenance
// before any owner SQL credential is used. It cannot accept a role manifest as
// authority, read the private role-creation journal or repair missing receipts.
type InstalledOwnerIdentityReader struct {
	client     *PermissionClient
	protection *OwnerWorkloadProtection
	input      contracts.OwnerDeployment
	activation contracts.OwnerIdentityActivation
	tokens     app.OwnerPodToken
	podUID     string
	reuse      *ownerIdentityReuse
}

// ownerIdentityReuse holds the last successful Verify for one exact mounted
// bundle. Like the guard proof it is reused for at most OwnerProtectionReuse,
// never past its token or guard bound; failures are never stored.
type ownerIdentityReuse struct {
	slot  chan struct{}
	key   [32]byte
	until time.Time
}

func NewInstalledOwnerIdentityReader(client *PermissionClient, protection *OwnerWorkloadProtection, input contracts.OwnerDeployment, activation contracts.OwnerIdentityActivation, tokens app.OwnerPodToken, podUID string) (*InstalledOwnerIdentityReader, error) {
	if client == nil || protection == nil || protection.observer != client || tokens == nil || !authorization.UUID(podUID) || !OwnerIdentityActivationBound(input, activation) || client.clusterID != input.ClusterID || client.control != (cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}) || protection.plan.Deployment != activation.Input.Deployment.Name || protection.plan.DeploymentUID != activation.Input.Deployment.UID || protection.plan.ControlNamespace != client.control || protection.plan.Name != input.WorkloadGuard.Name || protection.pin != (GuardPin{PolicyUID: input.WorkloadGuard.PolicyUID, PolicyGeneration: input.WorkloadGuard.PolicyGeneration, BindingUID: input.WorkloadGuard.BindingUID, BindingResourceVersion: input.WorkloadGuard.BindingResourceVersion}) {
		return nil, cfg.ErrInvalid
	}
	// Retain the caller's complete independently constructed guard, including
	// installation-only exceptions; never reconstruct a partial admission plan.
	raw, e := json.Marshal(struct {
		Input      contracts.OwnerDeployment
		Activation contracts.OwnerIdentityActivation
	}{input, activation})
	var copied struct {
		Input      contracts.OwnerDeployment
		Activation contracts.OwnerIdentityActivation
	}
	if e != nil || json.Unmarshal(raw, &copied) != nil {
		return nil, cfg.ErrInvalid
	}
	return &InstalledOwnerIdentityReader{client, protection, copied.Input, copied.Activation, tokens, podUID, &ownerIdentityReuse{slot: make(chan struct{}, 1)}}, nil
}

func (s *InstalledOwnerIdentityReader) get(ctx context.Context, path string, out any) error {
	raw, e := s.client.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return errors.Join(cfg.ErrUnavailable, e)
	}
	if permissionJSON(raw, 1<<20, 131072) != nil || strictGuardJSON(raw, out) != nil {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}

func (s *InstalledOwnerIdentityReader) journal(ctx context.Context) (result contracts.InitialRuntimeResourceState, err error) {
	check := ownerReadJournalRead
	defer ownerReadAnnotate(&check, &err)
	var zero contracts.InitialRuntimeResourceState
	a := s.activation
	in := a.Input
	var obj core.Secret
	if e := s.get(ctx, "/api/v1/namespaces/"+in.Namespace.Name+"/secrets/"+in.Resources.Name, &obj); e != nil {
		return zero, e
	}
	defer clearRuntimeProjection(obj.Data)
	check = ownerReadJournalMetadata
	if obj.APIVersion != "v1" || obj.Kind != "Secret" || !ownerMetadata(obj.ObjectMeta, in.Namespace.Name, in.Resources.Name, in.Resources.UID) || len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 || len(obj.Annotations) != 0 || obj.Type != core.SecretTypeOpaque || obj.Immutable != nil && *obj.Immutable || len(obj.StringData) != 0 || len(obj.Data) != 1 {
		return zero, cfg.ErrChanged
	}
	check = ownerReadJournalState
	v, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(obj.Data["state.json"]))
	if e != nil || v.Format != contracts.InitialRuntimeResourcesFormat || !ownerProviderJournalBound(s.input, a, v) || v.SetupID != in.ResourceSetupID || v.BindingDigest != in.ResourceBinding || !v.CreatedAt.Equal(a.ResourcesCreatedAt) || !v.Until.Equal(a.ResourcesUntil) || len(v.Objects) != len(initialRuntimeResourceItems) || !workerProjectionStateValid(in.InstallationID, v, s.client.now()) || v.OwnerIdentity == nil || v.OwnerIdentity.Receipt == nil || v.OwnerLaunch == nil || v.OwnerIdentity.RoleRoot != a.RoleRoot || v.OwnerIdentity.RoleSetupID != a.RoleSetupID {
		return zero, cfg.ErrChanged
	}
	check = ownerReadJournalReceipts
	ids := map[string]bool{v.SetupID: true}
	uids := map[string]bool{in.Resources.UID: true}
	for i, c := range v.Objects {
		if c.Item != initialRuntimeResourceItems[i] || !authorization.UUID(c.OperationID) || ids[c.OperationID] || !preparationDigestValid(c.TemplateDigest) || !ownerIdentityInterval(c.ClaimedAt, c.Until, v.CreatedAt, v.Until, s.client.now()) || c.Receipt == nil || !authorization.UUID(c.Receipt.UID) || uids[c.Receipt.UID] || !identity.Text(c.Receipt.ResourceVersion, 128) || c.Receipt.Generation < 0 || c.Receipt.Generation >= 1<<53 {
			return zero, cfg.ErrChanged
		}
		ids[c.OperationID], uids[c.Receipt.UID] = true, true
	}
	check = ownerReadJournalOriginalPins
	if v.Objects[0].Receipt.UID != in.ServiceAccount.UID || v.Objects[10].Receipt.UID != in.Deployment.UID || v.Objects[10].Receipt.Generation != 1 || v.Objects[14].Receipt.UID != in.OwnerConfigurationUID || v.Objects[17].Receipt.UID != s.input.WorkloadGuard.PolicyUID || v.Objects[17].Receipt.Generation != s.input.WorkloadGuard.PolicyGeneration || v.Objects[18].Receipt.UID != s.input.WorkloadGuard.BindingUID || v.Objects[18].Receipt.ResourceVersion != s.input.WorkloadGuard.BindingResourceVersion {
		return zero, cfg.ErrChanged
	}
	n := runtimeResourceNames(in.InstallationID)
	check = ownerReadJournalChildNames
	if v.OwnerIdentity.Receipt.Configuration.Name != n.OwnerInputs || v.OwnerIdentity.Receipt.Credentials.Name != n.OwnerProviders {
		return zero, cfg.ErrChanged
	}
	if v.OwnerLaunch.Receipt == nil {
		check = ownerReadLaunchReceipt
		return zero, &ownerLaunchReceiptPending{state: v}
	}
	return v, nil
}

// Verify compares the complete fixed mounted provider bundle with the immutable
// native Secret and checks the original positive launch. Current configuration,
// recovery, exact SQL roles and process registration remain later prerequisites.
// One successful proof of an identical bundle is reused by every caller for at
// most OwnerProtectionReuse (2026-10-23 revision of ADR-208); it proves the
// hub's own installation, which the trust model already trusts.
func (s *InstalledOwnerIdentityReader) Verify(ctx context.Context, manifest contracts.OwnerIdentityCredentialManifest, mounted map[string][]byte) (result time.Time, err error) {
	if s == nil || ctx == nil || s.reuse == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	raw, e := json.Marshal(struct {
		Manifest contracts.OwnerIdentityCredentialManifest
		Mounted  map[string][]byte
	}{manifest, mounted})
	key := sha256.Sum256(raw)
	clear(raw)
	if e != nil {
		return time.Time{}, cfg.ErrInvalid
	}
	if e = ctx.Err(); e != nil {
		return time.Time{}, &OwnerIdentityReadFailure{check: ownerReadInput, cause: cfg.ErrInvalid}
	}
	select {
	case s.reuse.slot <- struct{}{}:
	case <-ctx.Done():
		return time.Time{}, &OwnerIdentityReadFailure{check: ownerReadInput, cause: errors.Join(cfg.ErrUnavailable, ctx.Err())}
	}
	defer func() { <-s.reuse.slot }()
	if s.reuse.key != key || !s.client.now().Add(ownerProtectionRefresh).Before(s.reuse.until) {
		until, err := s.verify(ctx, manifest, mounted, nil)
		if err != nil {
			return time.Time{}, err
		}
		s.reuse.key, s.reuse.until = key, until
	}
	return callerBound(ctx, s.reuse.until), nil
}

func (s *InstalledOwnerIdentityReader) verify(ctx context.Context, manifest contracts.OwnerIdentityCredentialManifest, mounted map[string][]byte, expected *contracts.InitialRuntimeResourceState) (result time.Time, err error) {
	check := ownerReadInput
	defer ownerReadAnnotate(&check, &err)
	if s == nil || ctx == nil || ctx.Err() != nil || manifest.Format != contracts.OwnerIdentityCredentialManifestFormat || !equalJSON(manifest.Input, s.activation.Input) || manifest.RootUID != s.activation.RoleRoot.UID || manifest.SetupID != s.activation.RoleSetupID {
		return time.Time{}, cfg.ErrInvalid
	}
	started := s.client.now()
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer end()
	until := started.Add(OwnerProtectionReuse)
	check = ownerReadInitialGuard
	_, bound, e := s.protection.reused(call)
	if e != nil {
		return time.Time{}, e
	}
	until = identity.Earlier(until, bound)
	in := s.activation.Input
	check = ownerReadTokenRead
	token, e := s.tokens.ReadOwnerPodToken(call)
	defer clear(token)
	if e != nil || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) {
		return time.Time{}, errors.Join(cfg.ErrDenied, e)
	}
	check = ownerReadInitialTokenReview
	name, e := reviewBoundPodToken(call, s.client, token, OwnerEnrollmentAudience(in.InstallationID), in.Namespace.Name, in.ServiceAccount.Name, in.ServiceAccount.UID, s.podUID)
	if e != nil {
		return time.Time{}, errors.Join(cfg.ErrDenied, e)
	}
	check = ownerReadTokenInterval
	expiry, e := reviewedTokenExpiry(token, s.client.now())
	if e != nil {
		return time.Time{}, errors.Join(cfg.ErrDenied, e)
	}
	until = identity.Earlier(until, expiry)
	check = ownerReadInitialJournal
	before, e := s.journal(call)
	if e != nil {
		return time.Time{}, e
	}
	if expected != nil && !equalJSON(*expected, before) {
		return time.Time{}, cfg.ErrChanged
	}
	check = ownerReadProjections
	if e = s.projections(call, before, manifest, mounted); e != nil {
		return time.Time{}, e
	}
	check = ownerReadInitialDeployment
	if e = s.deployment(call, before); e != nil {
		return time.Time{}, e
	}
	// live is a native resource reader here, not an accepted configuration or
	// enrollment proof. Only these independently pinned original fields are used.
	pool := value.OwnerPool{InstallationID: in.InstallationID, ClusterID: in.ClusterID, Namespace: in.Namespace.Name, NamespaceUID: in.Namespace.UID, Deployment: in.Deployment.Name, DeploymentUID: in.Deployment.UID, ServiceAccount: in.ServiceAccount.Name, AccountUID: in.ServiceAccount.UID}
	reader := &OwnerEnrollmentAttester{client: s.client}
	check = ownerReadInitialPod
	if _, e = reader.live(call, pool, value.OwnerBinding{PodUID: s.podUID}, name); e != nil {
		return time.Time{}, e
	}
	check = ownerReadFinalDeadline
	if e = initialHandoverDeadline(call, s.client.now, until); e != nil {
		return time.Time{}, e
	}
	return until, nil
}
