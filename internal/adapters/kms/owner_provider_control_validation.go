package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func (c *ownerProviderControl) metadata(v map[string]string) bool {
	_, hasSecretName := v["service_account_secret_name"]
	return hasSecretName && len(v) == 5 && v["role"] == c.role && v["service_account_uid"] == c.accountUID && v["service_account_name"] == c.account && v["service_account_namespace"] == c.namespace && v["service_account_secret_name"] == ""
}

func (c *ownerProviderControl) validAuth(reply ownerProviderControlReply, old *ownerProviderCredential) bool {
	a := reply.Auth
	if a == nil || !ownerProviderNull(reply.Data) || !ValidProviderToken([]byte(a.ClientToken)) || !ValidProviderToken([]byte(a.Accessor)) || len(a.Accessor) > 512 || !authorization.UUID(a.EntityID) || a.EntityID == "00000000-0000-0000-0000-000000000000" || len(a.Policies) != 1 || a.Policies[0] != c.role || len(a.TokenPolicies) != 1 || a.TokenPolicies[0] != c.role || len(a.IdentityPolicies) != 0 || !c.metadata(a.Metadata) || !a.Orphan || !a.Renewable || a.Type != "service" || a.Uses != 0 || a.LeaseDuration < 1 || a.LeaseDuration > contracts.OwnerProviderTokenTTLSeconds || !ownerProviderNull(a.MFA) {
		return false
	}
	return old == nil || a.ClientToken == string(old.token) && a.Accessor == old.accessor && a.EntityID == old.entity
}

func (c *ownerProviderControl) lookup(ctx context.Context, token []byte, old *ownerProviderCredential, operationStart time.Time, auth *ownerProviderAuthReply, jwtUntil time.Time) (*ownerProviderCredential, error) {
	lookupStart := c.now()
	reply, err := c.call(ctx, http.MethodGet, "auth/token/lookup-self", token, nil)
	var value initialTokenLookup
	if err != nil || reply.Auth != nil || !initialProviderFields(reply.Data, "id", "accessor", "policies", "path", "meta", "display_name", "num_uses", "orphan", "creation_time", "creation_ttl", "expire_time", "ttl", "explicit_max_ttl", "entity_id", "type", "renewable", "issue_time") || !initialProviderDecode(reply.Data, &value) {
		return nil, ErrKeyService
	}
	observed := c.now()
	if ctx.Err() != nil || value.ID != string(token) || !ValidProviderToken([]byte(value.Accessor)) || len(value.Accessor) > 512 || !authorization.UUID(value.Entity) || value.Entity == "00000000-0000-0000-0000-000000000000" || len(value.Policies) != 1 || value.Policies[0] != c.role || len(value.IdentityPolicies) != 0 || value.Path != "auth/"+c.mount+"/login" || !c.metadata(value.Meta) || value.Uses != 0 || !value.Orphan || value.Type != "service" || !value.Renewable || value.Role != "" || value.Period != 0 || len(value.Bound) != 0 || value.MaxTTL != contracts.OwnerProviderTokenMaxTTLSeconds || value.CreationTTL < 1 || value.CreationTTL > contracts.OwnerProviderTokenTTLSeconds || value.TTL < 1 || value.TTL > contracts.OwnerProviderTokenTTLSeconds || value.Creation <= 0 || value.Issued.IsZero() || value.Issued.After(observed) || value.Issued.Unix() != value.Creation || !observed.Before(value.Expire) || value.LastRenewal < 0 || value.LastRenewal > observed.Unix() || value.LastRenewalDate.After(observed) {
		return nil, ErrKeyService
	}
	if (value.LastRenewal == 0) != value.LastRenewalDate.IsZero() || value.LastRenewal != 0 && (value.LastRenewalDate.Unix() != value.LastRenewal || value.LastRenewalDate.Before(value.Issued)) {
		return nil, ErrKeyService
	}
	// The provider's original issue instant fixes the hard maximum. Epoch-second
	// creation time is an additional conservative lower bound, never an excuse
	// to round the usable end upward.
	issued := value.Issued.UTC()
	hard := time.Unix(value.Creation, 0).UTC().Add(time.Duration(contracts.OwnerProviderTokenMaxTTLSeconds) * time.Second)
	if old != nil {
		if !bytes.Equal(old.token, token) || value.Accessor != old.accessor || value.Entity != old.entity || !issued.Equal(old.issued) || !hard.Equal(old.hardUntil) || !jwtUntil.Equal(old.jwtUntil) || value.CreationTTL != old.creationTTL {
			return nil, ErrKeyService
		}
	} else if auth == nil || value.Accessor != auth.Accessor || value.Entity != auth.EntityID || issued.Before(operationStart.Truncate(time.Second)) || value.LastRenewal != 0 || !value.LastRenewalDate.IsZero() {
		return nil, ErrKeyService
	}
	until := value.Expire.UTC()
	for _, bound := range []time.Time{hard, lookupStart.Add(time.Duration(value.TTL) * time.Second)} {
		if bound.Before(until) {
			until = bound
		}
	}
	if auth != nil {
		if bound := operationStart.Add(time.Duration(auth.LeaseDuration) * time.Second); bound.Before(until) {
			until = bound
		}
	}
	if !observed.Before(until) || ctx.Err() != nil {
		return nil, ErrKeyService
	}
	return &ownerProviderCredential{owner: c, token: bytes.Clone(token), accessor: value.Accessor, entity: value.Entity, issued: issued, hardUntil: hard, until: until, observed: observed, jwtUntil: jwtUntil, creationTTL: value.CreationTTL}, nil
}

// Parsing an unverified JWT supplies scheduling input only. It never extends a
// provider lease, verifies audience/account/Pod, or replaces online TokenReview.
// The pinned provider uses this original JWT again for renew-self; kubelet file
// rotation can only be consumed by a separate later login.
func ownerProviderJWTEnd(jwt []byte, now time.Time) (time.Time, error) {
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return time.Time{}, ErrKeyService
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	defer clear(raw)
	if err != nil || len(raw) > 12288 || !jsontext.Value(raw).IsValid() {
		return time.Time{}, ErrKeyService
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp <= 0 || claims.Exp > 253402300799 {
		return time.Time{}, ErrKeyService
	}
	end := time.Unix(claims.Exp, 0).UTC()
	if !now.Before(end) {
		return time.Time{}, ErrKeyService
	}
	return end, nil
}

// Refresh scheduling can advance toward an earlier unverified JWT exp; it
// cannot postpone the independently known provider maximum or usable end.
func (c *ownerProviderCredential) reauthenticateAt() time.Time {
	at := c.hardUntil.Add(-120 * time.Second)
	if jwt := c.jwtUntil.Add(-30 * time.Second); jwt.Before(at) {
		at = jwt
	}
	return at
}

func (c *ownerProviderCredential) renewAt() time.Time {
	at := c.observed.Add(120 * time.Second)
	if expiry := c.until.Add(-30 * time.Second); expiry.Before(at) {
		at = expiry
	}
	return at
}
