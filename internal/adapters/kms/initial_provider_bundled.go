package kms

import (
	"context"
	"net/http"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// A fixed margin makes the initial issuer and all its children expire before
// their original setup parent. It never extends a provider or installer bound.
const BundledInitialProviderSafetyMargin = contracts.BundledInitialProviderSafetyMargin

// ObserveBundledInitialProviderIdentity reads the actual setup login once; it
// does not log in, issue, renew or mutate. Native references are independently
// obtained by the trusted installer, never selected by a public caller.
func ObserveBundledInitialProviderIdentity(ctx context.Context, endpoint, setupToken string, plan contracts.SmallOpenBaoPlan, namespace, account contracts.WorkerObjectReference, h *http.Client, now func() time.Time) (contracts.BundledInitialProviderIdentity, error) {
	var zero contracts.BundledInitialProviderIdentity
	if ctx == nil || ctx.Err() != nil || !plan.Valid() || endpoint != plan.Endpoint() || namespace.Name != plan.Namespace || account.Name != plan.SetupAccount || !authorization.UUID(namespace.UID) || !authorization.UUID(account.UID) || !ValidProviderToken([]byte(setupToken)) || len(setupToken) > contracts.InitialProviderTokenMaxBytes || now == nil {
		return zero, ErrKeyService
	}
	c, err := client(endpoint, setupToken, h)
	if err != nil {
		return zero, err
	}
	r, _, err := initialProviderCall(ctx, c, http.MethodGet, "auth/token/lookup-self", nil)
	var d initialTokenLookup
	if err != nil || !initialProviderFields(r.Data, "accessor", "type", "policies", "meta", "num_uses", "orphan", "renewable", "entity_id", "creation_ttl", "explicit_max_ttl", "issue_time", "expire_time") || !initialProviderDecode(r.Data, &d) || !identity.Text(d.Accessor, 128) || !authorization.UUID(d.Entity) || len(d.IdentityPolicies) != 0 || !reflect.DeepEqual(d.Policies, []string{contracts.SmallOpenBaoSetupPolicy}) || d.Type != "service" || !d.Orphan || !d.Renewable || d.Period != 0 || d.Uses != 0 || len(d.Bound) != 0 || d.Path != "auth/"+contracts.SmallOpenBaoSetupMount+"/login" || d.Meta["role"] != contracts.SmallOpenBaoSetupRole || d.Meta["service_account_name"] != account.Name || d.Meta["service_account_namespace"] != namespace.Name || d.Meta["service_account_uid"] != account.UID || d.CreationTTL != 300 || d.MaxTTL != 900 || d.LastRenewal != 0 || !d.LastRenewalDate.IsZero() || d.Issued.IsZero() || d.Expire.IsZero() || now().Before(d.Issued) || !now().Before(d.Expire.Add(-BundledInitialProviderSafetyMargin)) || ctx.Err() != nil {
		return zero, ErrKeyService
	}
	for key, value := range d.Meta {
		switch key {
		case "role", "service_account_name", "service_account_namespace", "service_account_uid":
		case "service_account_secret_name":
			if value != "" {
				return zero, ErrKeyService
			}
		default:
			return zero, ErrKeyService
		}
	}
	selected := contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: plan.Name, Namespace: namespace, SetupAccount: account, EntityID: d.Entity, SetupParent: contracts.InitialProviderParent{Accessor: d.Accessor, IssuedAt: d.Issued.UTC(), ExpiresAt: d.Expire.UTC()}}
	if !selected.Valid() {
		return zero, ErrKeyService
	}
	return selected, nil
}

// NewBundledInitialProviderIssuer explicitly selects one independently checked
// service identity. The external constructor continues to require empty entity.
// The caller persists this original provenance beside the one original token;
// it must compare native namespace/account pins with its retained install plan.
func NewBundledInitialProviderIssuer(endpoint, token, mount, key, installation, request string, profile contracts.InitialProviderProfile, selected contracts.BundledInitialProviderIdentity, h *http.Client, now func() time.Time) (*InitialProviderIssuer, error) {
	if !selected.Valid() || endpoint != selected.Endpoint() || now == nil || now().Before(selected.SetupParent.IssuedAt) || !now().Before(selected.SetupParent.ExpiresAt.Add(-BundledInitialProviderSafetyMargin)) {
		return nil, ErrKeyService
	}
	s, err := NewInitialProviderIssuer(endpoint, token, mount, key, installation, request, profile, h, now)
	if err != nil {
		return nil, err
	}
	s.bundled = &selected
	return s, nil
}
func (s *InitialProviderIssuer) expectedEntity() string {
	if s.bundled != nil {
		return s.bundled.EntityID
	}
	return ""
}
func (s *InitialProviderIssuer) withinSetupBound(expiry time.Time) bool {
	return s.bundled == nil || (!expiry.After(s.bundled.SetupParent.ExpiresAt.Add(-BundledInitialProviderSafetyMargin)) && s.now().Before(s.bundled.SetupParent.ExpiresAt))
}
