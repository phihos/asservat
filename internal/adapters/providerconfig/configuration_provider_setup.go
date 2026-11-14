package providerconfig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/contracts"
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

// ContextDeletionSigningReadback is the context deletion signing key as the
// configuration readback observed it (ADR-205 decision 6): its latest
// version and the public key of each version Transit returned, for the
// installer to pin. It is an observation, never signing authority.
type ContextDeletionSigningReadback struct {
	Mount, Key string
	Version    int
	PublicKeys map[int]ed25519.PublicKey
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
