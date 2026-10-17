package kubernetes

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Actual original responses belonging to one admitted owner operation. This is
// neither a current-reader implementation nor a value supplied by an installer
// input. The SQL seam consumes the separately admitted opaque operation only.
type ownerIdentityOperationNative struct {
	retained initialRuntimeRetainedResources
	source   configurationWorkerNative
	input    contracts.OwnerIdentityRoles
	accepted fleet.OwnerConfigurationObservation
	account  core.ServiceAccount
	service  core.Service
	roles    contracts.OwnerIdentityRoleSnapshot
	object   *core.Secret
	missing  bool
	until    time.Time
}

// The caller owns the original root/resources/bridge/source lifetime. The first
// read-only bracket precedes the source-bound SQL bridge; the final bracket
// remains inside it. This fresh-only bracket never calls root.current/readResources
// or a cached legacy source. With no conflict it uses C12/B13/H7/S26 (S27 with
// roles), W4/T9; the actual denied Deployment also supplies original object10.
func (s *OwnerIdentityRoleRoot) readOwnerIdentityOperationNative(ctx context.Context, layout string, withRoles bool) (ownerIdentityOperationNative, error) {
	var zero ownerIdentityOperationNative
	if s == nil || s.bridge == nil || s.resources == nil || s.accepted == nil || ctx == nil || ctx.Err() != nil || s.resources.ownerLayout != contracts.OwnerProviderInstalledLayout || !ownerIdentityDigestValid(layout) {
		return zero, cfg.ErrInvalid
	}
	until, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrInvalid
	}
	// The two concrete read graphs are independent. A failed branch cancels the
	// other, and all started work joins before any response can authorize a claim.
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	var retained initialRuntimeRetainedResources
	var source configurationWorkerNative
	var failures [2]error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() {
		defer joined.Done()
		retained, failures[0] = s.bridge.readRetainedOriginalResources(call, s.resources)
		if failures[0] != nil {
			cancel()
		}
	}()
	go func() {
		defer joined.Done()
		source, failures[1] = s.bridge.source.readConfigurationWorkerNative(call)
		if failures[1] != nil {
			cancel()
		}
	}()
	joined.Wait()
	// Preserve the original joined branch precedence; this is not a claim
	// about which concurrent request failed first in wall-clock time.
	for i, err := range failures {
		if err != nil {
			check := ownerNativeRetained
			if i == 1 {
				check = ownerNativeSource
			}
			return zero, ownerOperationError(check, err)
		}
	}
	until = identity.Earlier(until, identity.Earlier(retained.until, source.proof.observation.FreshUntil))
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeInitialDeadline, cfg.ErrUnavailable)
	}
	input, err := s.inputFromResources(retained.resources, layout)
	if err != nil || input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return zero, ownerOperationError(ownerNativeInput, cfg.ErrChanged)
	}
	for _, claim := range retained.resources.State.Objects {
		if claim.Receipt == nil {
			return zero, ownerOperationError(ownerNativeReceipt, cfg.ErrChanged)
		}
	}
	if s.input.Format != "" && (input != s.input || !retained.resources.State.CreatedAt.Equal(s.resourceCreatedAt) || !retained.resources.State.Until.Equal(s.resourceUntil)) {
		return zero, ownerOperationError(ownerNativeOriginalInput, cfg.ErrChanged)
	}
	if !ownerIdentityOriginalConfiguration(s.resources, retained.resources.State, source.owner) {
		return zero, ownerOperationError(ownerNativeOriginalConfiguration, cfg.ErrChanged)
	}
	if err = s.ownerIdentityOperationDeployment(call, source.ownerDeployment, retained.resources.State, input); err != nil {
		return zero, ownerOperationError(ownerNativeDeployment, err)
	}
	reader := &OwnerEndpoints{client: s.bridge.source.client, pool: source.owner.Pool}
	account, err := ownerResource[core.ServiceAccount](reader, call, "/api/v1/namespaces/"+input.Namespace.Name+"/serviceaccounts/"+input.ServiceAccount.Name, "v1", "ServiceAccount")
	if err != nil {
		return zero, ownerOperationError(ownerNativeAccountRead, err)
	}
	if err = s.ownerIdentityOperationOriginalObject(call, account, retained.resources.State, 0); err != nil {
		return zero, ownerOperationError(ownerNativeAccountOriginal, err)
	}
	service, err := ownerResource[core.Service](reader, call, "/api/v1/namespaces/"+input.Namespace.Name+"/services/"+source.owner.Pool.Service, "v1", "Service")
	if err != nil {
		return zero, ownerOperationError(ownerNativeServiceRead, err)
	}
	if err = s.ownerIdentityOperationOriginalObject(call, service, retained.resources.State, 12); err != nil {
		return zero, ownerOperationError(ownerNativeServiceOriginal, err)
	}
	if err = s.ownerIdentityOperationProbes(call, account, source.account); err != nil {
		return zero, ownerOperationError(ownerNativeProbes, err)
	}
	accepted, err := s.accepted.ReadOwnerConfiguration(call)
	until = identity.Earlier(until, accepted.FreshUntil)
	// Keep the exact previous short-circuit order, including clock samples.
	// A failed reader was already normalized to unavailable here; do not expose
	// its driver error or add that error to the existing errors.Is contract.
	if err != nil {
		return zero, ownerOperationError(ownerNativeAcceptedRead, cfg.ErrUnavailable)
	}
	if !accepted.Valid(s.resources.now()) {
		return zero, ownerOperationError(ownerNativeAcceptedValid, cfg.ErrUnavailable)
	}
	if !accepted.Configuration.Equal(source.owner) {
		return zero, ownerOperationError(ownerNativeAcceptedEqual, cfg.ErrUnavailable)
	}
	if !ownerIdentityOriginalConfiguration(s.resources, retained.resources.State, accepted.Configuration) {
		return zero, ownerOperationError(ownerNativeAcceptedOriginal, cfg.ErrUnavailable)
	}
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeAcceptedDeadline, cfg.ErrUnavailable)
	}
	out := ownerIdentityOperationNative{retained: retained, source: source, input: input, accepted: accepted, account: account, service: service, until: until}
	if withRoles {
		// The native root constructor must have fixed its input before a private
		// journal can be read. No caller-selected name or current UID is adopted.
		if s.input != input {
			return zero, cfg.ErrChanged
		}
		bounded, stop := context.WithDeadline(call, until)
		defer stop()
		raw, err := s.bridge.source.client.api.Get().AbsPath(s.path() + "/" + s.name()).MaxRetries(0).DoRaw(bounded)
		defer clear(raw)
		if apierrors.IsNotFound(err) {
			if s.operationRootUID != "" {
				return zero, cfg.ErrChanged
			}
			out.missing = true
		} else if err != nil {
			return zero, err
		} else {
			out.roles, out.object, err = s.decode(raw, until)
			if err != nil {
				return zero, err
			}
			if s.operationRootUID != "" && out.roles.UID != s.operationRootUID || s.pendingOperationRoot != nil && !equalJSON(out.roles.State, *s.pendingOperationRoot) {
				return zero, cfg.ErrChanged
			}

		}
	}
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeFinalDeadline, cfg.ErrUnavailable)
	}
	return out, nil
}

func (s *OwnerIdentityRoleRoot) ownerIdentityOperationOriginalObject(ctx context.Context, object any, state contracts.InitialRuntimeResourceState, index int) error {
	raw, err := json.Marshal(object)
	if err != nil {
		return cfg.ErrChanged
	}
	_, err = s.resources.verified(ctx, raw, state, index)
	return err
}

func (s *OwnerIdentityRoleRoot) ownerIdentityOperationDeployment(ctx context.Context, deployment apps.Deployment, state contracts.InitialRuntimeResourceState, input contracts.OwnerIdentityRoles) error {
	err := s.ownerIdentityOperationOriginalObject(ctx, deployment, state, 10)
	if err == nil && (state.OwnerLaunch == nil || state.OwnerLaunch.Receipt == nil) {
		return nil
	}
	if state.OwnerLaunch == nil || !ownerIdentityClaimedLaunchObject(deployment, state, input) {
		return cfg.ErrChanged
	}
	// This is the exact already-spent transition, not permission to accept a
	// generally running owner or to mutate the retained original template.
	original := deployment.DeepCopy()
	*original.Spec.Replicas = 0
	delete(original.Annotations, ownerIdentityLaunchMarker)
	original.Generation = 1
	return s.ownerIdentityOperationOriginalObject(ctx, original, state, 10)
}

// All four explicit bindings retain separate actual SSR calls. The immutable
// fresh inventory requires two exact original accounts; only their duplicate
// GETs are removed. Wrong bindings reject rather than selecting a fallback.
func (s *OwnerIdentityRoleRoot) ownerIdentityOperationProbes(ctx context.Context, owner, worker core.ServiceAccount) error {
	check := func(client *PermissionClient, name, uid string, actual core.ServiceAccount) error {
		if client == nil || !ownerMetadata(actual.ObjectMeta, s.bridge.initial.Namespace.Name, name, uid) {
			return cfg.ErrChanged
		}
		raw, err := client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
		var who auth.SelfSubjectReview
		if err != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.bridge.initial.Namespace.Name+":"+name || who.Status.UserInfo.UID != uid {
			return cfg.ErrUnavailable
		}
		return s.bridge.deadline(ctx)
	}
	p := s.bridge.administration.OwnerProbe
	if p.ServiceAccount != owner.Name || p.ServiceAccountUID != string(owner.UID) || len(s.bridge.administration.SourceProbes) != 3 {
		return cfg.ErrChanged
	}
	if err := check(s.bridge.source.protection.probe, p.ServiceAccount, p.ServiceAccountUID, owner); err != nil {
		return err
	}
	for _, p := range s.bridge.administration.SourceProbes {
		if p.ServiceAccount != worker.Name || p.ServiceAccountUID != string(worker.UID) {
			return cfg.ErrChanged
		}
		client := s.bridge.source.owner.protection.probe
		if p.ConfigMap == s.bridge.source.input.FleetSource.Name {
			client = s.bridge.source.fleet.protection.probe
		}
		if err := check(client, p.ServiceAccount, p.ServiceAccountUID, worker); err != nil {
			return err
		}
	}
	return nil
}
