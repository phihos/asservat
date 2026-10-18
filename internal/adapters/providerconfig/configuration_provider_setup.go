package providerconfig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// ConfigurationSetupCheck can only be produced by the concrete installer
// reader. It is finite provider readback, not Kubernetes custody, SQL recovery,
// backend capability, runtime authorization or an atomic fence against later
// changes by the trusted provider administrator.
type ConfigurationSetupCheck struct {
	binding           [32]byte
	observedAt, until time.Time
	signing           *ContextDeletionSigningReadback
}

func (o ConfigurationSetupCheck) ObservedAt() time.Time { return o.observedAt }
func (o ConfigurationSetupCheck) FreshUntil() time.Time { return o.until }

// ContextDeletionSigningReadback is the context deletion signing key as the
// configuration readback observed it (ADR-205 decision 6): its latest
// version and the public key of each version Transit returned, for the
// installer to pin. It is an observation, never signing authority.
type ContextDeletionSigningReadback struct {
	Mount, Key string
	Version    int
	PublicKeys map[int]ed25519.PublicKey
}

// ContextDeletionSigning returns a copy of the observed signing key, or false
// for a profile without one.
func (o ConfigurationSetupCheck) ContextDeletionSigning() (ContextDeletionSigningReadback, bool) {
	if o.signing == nil {
		return ContextDeletionSigningReadback{}, false
	}
	out := *o.signing
	out.PublicKeys = make(map[int]ed25519.PublicKey, len(o.signing.PublicKeys))
	for v, k := range o.signing.PublicKeys {
		out.PublicKeys[v] = bytes.Clone(k)
	}
	return out, true
}
func (o ConfigurationSetupCheck) Matches(in contracts.HubWorkerDeployment, profile contracts.ConfigurationProviderAuthentication, now time.Time) bool {
	if o.binding == ([32]byte{}) || ValidateConfigurationProviderAuthentication(in, profile, now) != nil || o.observedAt.IsZero() || now.Before(o.observedAt) || !now.Before(o.until) || o.until.Sub(o.observedAt) > 5*time.Second {
		return false
	}
	binding, err := configurationSetupBinding(in, profile)
	return err == nil && o.binding == binding
}

func configurationSetupBinding(in contracts.HubWorkerDeployment, profile contracts.ConfigurationProviderAuthentication) ([32]byte, error) {
	body, err := json.Marshal(in)
	if err != nil || len(body) > contracts.OwnerDeploymentMaxBytes {
		return [32]byte{}, ErrSetupUnavailable
	}
	raw, err := json.Marshal(struct {
		Format  string                                        `json:"format"`
		Input   contracts.HubWorkerDeployment                 `json:"input"`
		Profile contracts.ConfigurationProviderAuthentication `json:"profile"`
	}{"asservat-configuration-provider-setup-check/v1", in, profile})
	if err != nil || len(raw) > contracts.OwnerDeploymentMaxBytes+contracts.ConfigurationProviderAuthenticationMaxBytes+256 {
		return [32]byte{}, ErrSetupUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize(jsontext.CanonicalizeRawInts(false)) != nil {
		return [32]byte{}, ErrSetupUnavailable
	}
	return sha256.Sum256(canonical), nil
}

// VerifyConfiguration checks exactly the generated two audit purposes. It
// never writes provider configuration or issues a token; the inspection token
// stays only in the separately owned SetupReader. Endpoint and original caller
// bounds are checked by begin before the first named GET.
func (r *SetupReader) VerifyConfiguration(ctx context.Context, in contracts.HubWorkerDeployment, profile contracts.ConfigurationProviderAuthentication) (ConfigurationSetupCheck, error) {
	var zero ConfigurationSetupCheck
	if ctx == nil || ctx.Err() != nil || ValidateConfigurationProviderAuthentication(in, profile, time.Now()) != nil {
		return zero, ErrSetupUnavailable
	}
	binding, err := configurationSetupBinding(in, profile)
	if err != nil {
		return zero, ErrSetupUnavailable
	}
	recipe, err := ConfigurationProviderRecipeFor(in, configurationProviderSelectionOf(profile), profile.ServiceAccount, time.Now())
	if err != nil {
		return zero, ErrSetupUnavailable
	}
	paths := []string{"sys/mounts/auth/" + profile.AuthMount, "auth/" + profile.AuthMount + "/config",
		"sys/mounts/" + in.KeyService.AuditMount, in.KeyService.AuditMount + "/keys/" + in.KeyService.AuditKey}
	for _, role := range recipe.Roles {
		paths = append(paths, "sys/policies/acl/"+role.Name, "auth/"+profile.AuthMount+"/role/"+role.Name)
	}
	// ADR-204: the worker configuration audit key, read after the purposes
	// (whose policies the recipe already extends to it).
	worker := profile.WorkerConfigurationAudit
	var workerReads []string
	if worker != (contracts.OwnerPublicTransit{}) {
		workerReads = configurationWorkerAuditReads(in, worker)
		paths = append(paths, workerReads...)
	}
	// ADR-205: the context deletion signing key, on the configuration audit
	// mount already read.
	signing := profile.ContextDeletionSigning
	if signing != (contracts.OwnerPublicTransit{}) {
		paths = append(paths, signing.Mount+"/keys/"+signing.Key)
	}
	o, err := r.begin(ctx, contracts.OwnerProviderEndpoint{Endpoint: in.KeyService.Endpoint, Roots: in.KeyService.Roots}, paths)
	if err != nil {
		return zero, err
	}
	defer o.finish()
	data, err := o.get(paths[0])
	if err != nil || verifyAuthMount(data, profile.AuthMountAccessor) != nil {
		return zero, setupComponentError("configuration auth mount")
	}
	data, err = o.get(paths[1])
	if err != nil || verifyKubernetesAuthConfig(data, in.Kubernetes) != nil {
		return zero, setupComponentError("configuration Kubernetes authentication")
	}
	data, err = o.get(paths[2])
	if err != nil || verifyTransitMount(data) != nil {
		return zero, setupComponentError("configuration Transit mount")
	}
	data, err = o.get(paths[3])
	if err != nil || verifyTransitKey(data, in.KeyService.AuditKey) != nil {
		return zero, setupComponentError("configuration Transit key")
	}
	for i, role := range recipe.Roles {
		data, err = o.get(paths[4+2*i])
		if err != nil || verifyACL(data, role.Name, role.Policy) != nil {
			return zero, setupComponentError("configuration purpose policy")
		}
		data, err = o.get(paths[5+2*i])
		if err != nil || verifyKubernetesRole(data, role.Role) != nil {
			return zero, setupComponentError("configuration purpose role")
		}
	}
	if len(workerReads) == 2 {
		data, err = o.get(workerReads[0])
		if err != nil || verifyTransitMount(data) != nil {
			return zero, setupComponentError("worker configuration Transit mount")
		}
	}
	if len(workerReads) > 0 {
		data, err = o.get(workerReads[len(workerReads)-1])
		if err != nil || verifyTransitKey(data, worker.Key) != nil {
			return zero, setupComponentError("worker configuration Transit key")
		}
	}
	var observed *ContextDeletionSigningReadback
	if signing != (contracts.OwnerPublicTransit{}) {
		data, err = o.get(paths[len(paths)-1])
		if err != nil {
			return zero, setupComponentError("context deletion signing key")
		}
		version, keys, e := verifySigningKeyVersions(data, signing.Key)
		if e != nil {
			return zero, setupComponentError("context deletion signing key")
		}
		observed = &ContextDeletionSigningReadback{Mount: signing.Mount, Key: signing.Key, Version: version, PublicKeys: keys}
	}
	if !o.valid() {
		return zero, ErrSetupUnavailable
	}
	until := o.until
	for _, anchors := range [][][]byte{in.Kubernetes.Roots, in.Postgres.Roots, in.AuditStore.Roots, in.KeyService.Roots} {
		_, end, e := mtls.OwnerTrustRoots(anchors, time.Now())
		if e != nil {
			return zero, ErrSetupUnavailable
		}
		until = identity.Earlier(until, end)
	}
	out := ConfigurationSetupCheck{binding: binding, observedAt: o.observedAt, until: until, signing: observed}
	if !out.Matches(in, profile, time.Now()) {
		return zero, ErrSetupUnavailable
	}
	return out, nil
}
