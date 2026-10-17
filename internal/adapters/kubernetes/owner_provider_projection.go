package kubernetes

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// NewProviderOwnerIdentityProjection selects only the complete original v2.
// Provider setup is read through the concrete named read-only adapter; callers
// cannot replace it with a timestamp, callback or a synthetic success flag.
// Runtime credentials and provider administrator authority never enter the
// immutable SQL projection. The caller retains ownership of setup.Close.
func NewProviderOwnerIdentityProjection(root *OwnerIdentityRoleRoot, verification OwnerIdentityRoleVerification, input contracts.OwnerDeployment, setup *providerconfig.SetupReader) (*OwnerIdentityProjection, error) {
	if root == nil || root.resources == nil || setup == nil || root.input.OwnerLayout != contracts.OwnerProviderInstalledLayout || input.ProviderAuthentication == nil || !ownerProviderProjectionSelectionBound(root, input, root.resources.now()) {
		return nil, cfg.ErrInvalid
	}
	return newOwnerIdentityProjection(root, verification, input, OwnerIdentityProviderMaterial{}, setup)
}

func ownerProviderProjectionSelectionBound(root *OwnerIdentityRoleRoot, in contracts.OwnerDeployment, now time.Time) bool {
	if root == nil || root.resources == nil || root.input.OwnerLayout != root.resources.ownerLayout || !initialRuntimeProviderSelectionValid(in.InstallationID, root.resources.workerLayout, root.resources.ownerLayout, root.resources.workerProvider, root.resources.ownerProvider) {
		return false
	}
	switch root.input.OwnerLayout {
	case contracts.OwnerInstalledLayout:
		return in.ProviderAuthentication == nil
	case contracts.OwnerProviderInstalledLayout:
		p := in.ProviderAuthentication
		return p != nil && root.resources.ownerProvider != nil && *root.resources.ownerProvider == ownerProviderSelectionFromProfile(*p) && p.ServiceAccount == root.input.ServiceAccount && providerconfig.ValidateOwnerProviderAuthentication(in, *p, now) == nil
	default:
		return false
	}
}

// Whole-call ownership also covers provider inspection before the SQL bridge
// callback. Closing either original component cancels and joins that I/O;
// entering the later bridge operation does not detach this outer borrow.
func (s *OwnerIdentityProjection) borrowProviderCall(ctx context.Context) (context.Context, func(), error) {
	if s.setup == nil {
		return ctx, func() {}, nil
	}
	r := s.root
	r.mu.Lock()
	if r.closed || r.ctx == nil || r.ctx.Err() != nil {
		r.mu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	r.joined.Add(1)
	r.mu.Unlock()
	call, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	stop := context.AfterFunc(r.ctx, func() { cancel(); close(done) })
	finish := func() {
		cancel()
		if !stop() {
			<-done
		}
		r.joined.Done()
	}
	call, release, err := r.resources.borrowWorkerProjection(call)
	if err != nil {
		finish()
		return nil, nil, err
	}
	return call, func() { release(); finish() }, nil
}

type ownerIdentityProviderObservation struct {
	configuration fleet.OwnerConfiguration
	check         providerconfig.OwnerSetupCheck
	until         time.Time
}

// Provider HTTP occurs before the bridge callback acquires SQL locks. The
// original caller/role/source intervals bound this observation and every later
// native operation. No observed interval becomes a persisted authority field.
func (s *OwnerIdentityProjection) observeProvider(ctx context.Context) (ownerIdentityProviderObservation, error) {
	var out ownerIdentityProviderObservation
	if s.setup == nil {
		if s.input.ProviderAuthentication != nil {
			return out, cfg.ErrInvalid
		}
		return out, nil
	}
	if !ownerProviderProjectionSelectionBound(s.root, s.input, s.root.resources.now()) {
		return out, cfg.ErrChanged
	}
	first, err := s.root.accepted.ReadOwnerConfiguration(ctx)
	if err != nil || !first.Valid(s.root.resources.now()) || first.Configuration.Suspended || first.Configuration.Revision.UID != s.root.input.OwnerConfigurationUID {
		return out, cfg.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, first.FreshUntil)
	defer end()
	check, err := s.setup.VerifyOwner(call, s.input, *s.input.ProviderAuthentication, first.Configuration.Pool, first.Configuration.IssuerRoots)
	if err != nil {
		return out, cfg.ErrUnavailable
	}
	until := identity.Earlier(first.FreshUntil, check.FreshUntil())
	if !check.Matches(s.input, *s.input.ProviderAuthentication, first.Configuration.Pool, first.Configuration.IssuerRoots, s.root.resources.now()) || initialHandoverDeadline(call, s.root.resources.now, until) != nil {
		return out, cfg.ErrUnavailable
	}
	return ownerIdentityProviderObservation{configuration: first.Configuration.Clone(), check: check, until: until}, nil
}

// The existing complete source reads retain their enforcement and original
// bounds, now also requiring the exact accepted revision inspected above.
func (s *OwnerIdentityProjection) currentProvider(ctx context.Context, p ownerIdentityProviderObservation) (time.Time, bool, error) {
	if s.setup == nil {
		return s.root.current(ctx)
	}
	if !s.providerCheckValid(ctx, p) {
		return time.Time{}, false, cfg.ErrUnavailable
	}
	until, launched, err := s.root.currentConfiguration(ctx, &p.configuration)
	until = identity.Earlier(until, p.until)
	if err != nil || !s.providerCheckValid(ctx, p) || initialHandoverDeadline(ctx, s.root.resources.now, until) != nil {
		return time.Time{}, false, cfg.ErrUnavailable
	}
	return until, launched, nil
}
func (s *OwnerIdentityProjection) providerCheckValid(ctx context.Context, p ownerIdentityProviderObservation) bool {
	return s.input.ProviderAuthentication != nil && ctx.Err() == nil && s.root.resources.now().Before(p.until) && p.check.Matches(s.input, *s.input.ProviderAuthentication, p.configuration.Pool, p.configuration.IssuerRoots, s.root.resources.now())
}

// The selected mutable Secret is an independently guarded credential source,
// never part of the immutable SQL Secret or public digest. Shape/readback does
// not prove an external storage administrator's policy or backend capability.
func (s *OwnerIdentityProjection) providerMaterialCurrent(ctx context.Context, snapshot contracts.InitialRuntimeResourceSnapshot, p ownerIdentityProviderObservation) error {
	if s.setup == nil {
		return nil
	}
	if !ownerProviderJournalBound(s.input, contracts.OwnerIdentityActivation{Input: s.root.input, ResourcesCreatedAt: snapshot.State.CreatedAt, ResourcesUntil: snapshot.State.Until}, snapshot.State) || !ownerIdentityOriginalConfiguration(s.root.resources, snapshot.State, p.configuration) || !s.providerCheckValid(ctx, p) {
		return cfg.ErrChanged
	}
	selected := s.input.ProviderAuthentication.AuditCredentials
	raw, err := s.root.bridge.source.client.api.Get().AbsPath("/api/v1/namespaces/" + s.input.Namespace.Name + "/secrets/" + selected.Name).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return cfg.ErrUnavailable
	}
	var object core.Secret
	if permissionJSON(raw, 64<<10, 4096) != nil || strictGuardJSON(raw, &object) != nil {
		return cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	if !initialProviderSecretIdentity(object, s.input.Namespace.Name, selected, contracts.OwnerProviderAuditCredentialFile) || !ownerProviderAuditMaterial(object.Data[contracts.OwnerProviderAuditCredentialFile]) {
		return cfg.ErrChanged
	}
	_, _, err = s.currentProvider(ctx, p)
	return err
}

func ownerProviderAuditMaterial(b []byte) bool {
	if len(b) == 0 || len(b) > 32<<10 {
		return false
	}
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	return err == nil && identity.Text(c.AccessKeyID, 256) && identity.Text(c.SecretAccessKey, 4096) && (c.SessionToken == "" || identity.Text(c.SessionToken, 16384))
}

// ownerPromotionAdmitted admits Native and Public sections only for the
// provider-installed layout (ADR-184): Public needs Native, the fixed public
// port and the pinned public provider recipe. The owner's startup reader
// validates the remaining contents.
func ownerPromotionAdmitted(layout string, in contracts.OwnerDeployment, now time.Time) bool {
	if in.Native == nil && in.Public == nil {
		return true
	}
	if layout != contracts.OwnerProviderInstalledLayout || in.Native == nil || in.ProviderAuthentication == nil {
		return false
	}
	return in.Public == nil || in.Public.Port == contracts.OwnerInstalledPublicPort && providerconfig.ValidateOwnerPublicProviderRecipe(in, *in.ProviderAuthentication, now) == nil &&
		in.Public.RuntimeProjection.Name == contracts.PublicRuntimeProjectionName(in.InstallationID) && authorization.UUID(in.Public.RuntimeProjection.UID)
}
