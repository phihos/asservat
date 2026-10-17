package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	bao "github.com/openbao/openbao/api/v2"
)

// InitialProviderIssuer is installation-only. The caller must persist its
// original one-use issue claim before Issue, own/join each call, and never replay
// it after an unknown response. Check and Verify are read-only and cannot recover
// the secret from an accessor. No KMS administrator token enters the target Pod.
type InitialProviderIssuer struct {
	client                            *bao.Client
	profile                           contracts.InitialProviderProfile
	installation, request, mount, key string
	now                               func() time.Time
}

func NewInitialProviderIssuer(endpoint, token, mount, key, installation, request string, profile contracts.InitialProviderProfile, h *http.Client, now func() time.Time) (*InitialProviderIssuer, error) {
	if !providerconfig.InitialProviderProfile(profile) || !keyName.MatchString(mount) || !keyName.MatchString(key) || !authorization.UUID(installation) || !authorization.UUID(request) || !ValidProviderToken([]byte(token)) || len(token) > contracts.InitialProviderTokenMaxBytes || now == nil {
		return nil, ErrKeyService
	}
	c, e := client(endpoint, token, h)
	if e != nil {
		return nil, e
	}
	return &InitialProviderIssuer{client: c, profile: profile, installation: installation, request: request, mount: mount, key: key, now: now}, nil
}
func (s *InitialProviderIssuer) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}

type initialProviderReply struct {
	Data     json.RawMessage      `json:"data"`
	Auth     *initialProviderAuth `json:"auth"`
	Warnings []string             `json:"warnings"`
	Wrap     json.RawMessage      `json:"wrap_info"`
}
type initialProviderAuth struct {
	bao.SecretAuth
	Type string `json:"token_type"`
	Uses int    `json:"num_uses"`
}

func initialProviderCall(ctx context.Context, c *bao.Client, method, path string, body any) (initialProviderReply, int, error) {
	var zero initialProviderReply
	if ctx == nil || ctx.Err() != nil || c == nil {
		return zero, 0, ErrKeyService
	}
	r := c.NewRequest(method, "/v1/"+path)
	if body != nil && r.SetJSONBody(body) != nil {
		return zero, 0, ErrKeyService
	}
	response, e := c.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if response == nil {
		return zero, 0, ErrKeyService
	}
	status := response.StatusCode
	if e != nil || status != http.StatusOK && status != http.StatusNoContent {
		return zero, status, ErrKeyService
	}
	if status == http.StatusNoContent {
		if ctx.Err() != nil {
			return zero, status, ErrKeyService
		}
		return zero, status, nil
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(raw)
	if e != nil || len(raw) > 32768 || !jsontext.Value(raw).IsValid() || json.Unmarshal(raw, &zero) != nil || len(zero.Warnings) != 0 || len(zero.Wrap) > 0 && string(zero.Wrap) != "null" || ctx.Err() != nil {
		return initialProviderReply{}, status, ErrKeyService
	}
	if zero.Auth != nil {
		var outer map[string]json.RawMessage
		if json.Unmarshal(raw, &outer) != nil || !initialProviderFields(outer["auth"], "client_token", "accessor", "token_type", "policies", "token_policies", "metadata", "lease_duration", "renewable", "orphan", "entity_id", "num_uses") {
			return initialProviderReply{}, status, ErrKeyService
		}
	}
	return zero, status, nil
}
func initialProviderFields(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range names {
		v, ok := fields[name]
		if !ok || len(v) == 0 || string(v) == "null" {
			return false
		}
	}
	return true
}
func initialProviderDecode(raw []byte, out any) bool {
	if len(raw) == 0 || !jsontext.Value(raw).IsValid() {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

type initialTokenRole struct {
	Name           string   `json:"name"`
	Allowed        []string `json:"allowed_policies"`
	Disallowed     []string `json:"disallowed_policies"`
	AllowedGlob    []string `json:"allowed_policies_glob"`
	DisallowedGlob []string `json:"disallowed_policies_glob"`
	Aliases        []string `json:"allowed_entity_aliases"`
	Orphan         bool     `json:"orphan"`
	Renewable      bool     `json:"renewable"`
	NoDefault      bool     `json:"token_no_default_policy"`
	Type           string   `json:"token_type"`
	Suffix         string   `json:"path_suffix"`
	Period         int64    `json:"period"`
	TokenPeriod    int64    `json:"token_period"`
	MaxTTL         int64    `json:"explicit_max_ttl"`
	TokenMaxTTL    int64    `json:"token_explicit_max_ttl"`
	Uses           int64    `json:"token_num_uses"`
	Bound          []string `json:"bound_cidrs"`
	TokenBound     []string `json:"token_bound_cidrs"`
}
type initialTokenLookup struct {
	ID               string            `json:"id"`
	Accessor         string            `json:"accessor"`
	Policies         []string          `json:"policies"`
	IdentityPolicies []string          `json:"identity_policies"`
	Path             string            `json:"path"`
	Meta             map[string]string `json:"meta"`
	Display          string            `json:"display_name"`
	Uses             int64             `json:"num_uses"`
	Orphan           bool              `json:"orphan"`
	Creation         int64             `json:"creation_time"`
	CreationTTL      int64             `json:"creation_ttl"`
	Expire           time.Time         `json:"expire_time"`
	TTL              int64             `json:"ttl"`
	MaxTTL           int64             `json:"explicit_max_ttl"`
	Entity           string            `json:"entity_id"`
	Type             string            `json:"type"`
	Role             string            `json:"role"`
	Period           int64             `json:"period"`
	Bound            []string          `json:"bound_cidrs"`
	Renewable        bool              `json:"renewable"`
	Issued           time.Time         `json:"issue_time"`
	LastRenewal      int64             `json:"last_renewal_time"`
	LastRenewalDate  time.Time         `json:"last_renewal"`
}

func (s *InitialProviderIssuer) purpose(purpose string) (string, string, bool) {
	switch purpose {
	case "wrap":
		return s.profile.WrapRole, s.profile.WrapPolicy, true
	case "unwrap":
		return s.profile.UnwrapRole, s.profile.UnwrapPolicy, true
	default:
		return "", "", false
	}
}
func (s *InitialProviderIssuer) role(ctx context.Context, name, policy string) error {
	r, _, e := initialProviderCall(ctx, s.client, http.MethodGet, "auth/token/roles/"+name, nil)
	var d initialTokenRole
	if e != nil || !initialProviderFields(r.Data, "name", "orphan", "renewable", "token_no_default_policy", "token_type", "period", "token_period", "explicit_max_ttl", "token_explicit_max_ttl") || !initialProviderDecode(r.Data, &d) || d.Name != name || !reflect.DeepEqual(d.Allowed, []string{policy}) || len(d.Disallowed)+len(d.AllowedGlob)+len(d.DisallowedGlob)+len(d.Aliases)+len(d.Bound)+len(d.TokenBound) != 0 || d.Orphan || d.Renewable || !d.NoDefault || d.Type != "service" || d.Suffix != "" || d.Period != 0 || d.TokenPeriod != 0 || d.Uses != 0 || d.TokenMaxTTL != 900 || d.MaxTTL != 0 && d.MaxTTL != d.TokenMaxTTL {
		return ErrKeyService
	}
	return nil
}

type initialACLRule struct {
	Capabilities []string `json:"capabilities"`
}
type initialACL struct {
	Path map[string]initialACLRule `json:"path"`
}

// InitialProviderPolicies supplies exact finite JSON ACLs for protected provider
// configuration. It creates no policy, role or token and is not source acceptance.
func InitialProviderPolicies(profile contracts.InitialProviderProfile, mount, key string) (map[string]string, error) {
	if !providerconfig.InitialProviderProfile(profile) || !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, ErrKeyService
	}
	return initialProviderPolicyBodies(profile.IssuerPolicy, profile.WrapRole, profile.WrapPolicy, profile.UnwrapRole, profile.UnwrapPolicy, mount, key)
}

// InitialBootstrapProviderPolicies exposes the same exact public prerequisites
// before any material object exists. No synthetic UID/profile, API access or
// provider acceptance is involved; runtime full-profile checks are unchanged.
func InitialBootstrapProviderPolicies(names contracts.InitialBootstrapProviders, mount, key string) (map[string]string, error) {
	if !providerconfig.InitialProviderNames(names.IssuerPolicy, names.WrapRole, names.WrapPolicy, names.UnwrapRole, names.UnwrapPolicy) || !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, ErrKeyService
	}
	return initialProviderPolicyBodies(names.IssuerPolicy, names.WrapRole, names.WrapPolicy, names.UnwrapRole, names.UnwrapPolicy, mount, key)
}

func initialProviderPolicyBodies(issuerPolicy, wrapRole, wrapPolicy, unwrapRole, unwrapPolicy, mount, key string) (map[string]string, error) {
	paths := map[string]initialACLRule{"auth/token/lookup-self": {[]string{"read"}}, "auth/token/lookup-accessor": {[]string{"update"}}, "auth/token/revoke-accessor": {[]string{"update"}}}
	for _, role := range []string{wrapRole, unwrapRole} {
		paths["auth/token/roles/"+role] = initialACLRule{[]string{"read"}}
		paths["auth/token/create/"+role] = initialACLRule{[]string{"update"}}
	}
	for _, policy := range []string{issuerPolicy, wrapPolicy, unwrapPolicy} {
		paths["sys/policies/acl/"+policy] = initialACLRule{[]string{"read"}}
	}
	specs := map[string]initialACL{issuerPolicy: {paths}, wrapPolicy: {map[string]initialACLRule{"auth/token/lookup-self": {[]string{"read"}}, mount + "/encrypt/" + key: {[]string{"update"}}}}, unwrapPolicy: {map[string]initialACLRule{"auth/token/lookup-self": {[]string{"read"}}, mount + "/decrypt/" + key: {[]string{"update"}}}}}
	out := map[string]string{}
	for name, v := range specs {
		b, e := json.Marshal(v)
		if e != nil {
			return nil, ErrKeyService
		}
		out[name] = string(b)
	}
	return out, nil
}
func (s *InitialProviderIssuer) policies(ctx context.Context) error {
	expected, e := InitialProviderPolicies(s.profile, s.mount, s.key)
	if e != nil {
		return e
	}
	for _, name := range []string{s.profile.IssuerPolicy, s.profile.WrapPolicy, s.profile.UnwrapPolicy} {
		r, _, e := initialProviderCall(ctx, s.client, http.MethodGet, "sys/policies/acl/"+name, nil)
		// Pinned OpenBao 2.7.1 readPolicyResponse includes finite policy
		// metadata as well as its body. These values do not renew authority.
		var value struct {
			Name           string     `json:"name"`
			Policy         string     `json:"policy"`
			Version        int64      `json:"version"`
			CASRequired    bool       `json:"cas_required"`
			AllowWildcards bool       `json:"allow_wildcards_in_identity_templates"`
			AllowSlashes   bool       `json:"allow_slashes_in_identity_templates"`
			Modified       *time.Time `json:"modified"`
			Expiration     *time.Time `json:"expiration"`
		}
		if e != nil || !initialProviderFields(r.Data, "name", "policy", "version", "cas_required", "allow_wildcards_in_identity_templates", "allow_slashes_in_identity_templates") || !initialProviderDecode(r.Data, &value) || value.Name != name || len(value.Policy) > 8192 || value.Version < 0 || value.AllowWildcards || value.AllowSlashes || value.Expiration != nil || value.Modified != nil && value.Modified.IsZero() {
			return ErrKeyService
		}
		var got, want initialACL
		if !initialProviderDecode([]byte(value.Policy), &got) || json.Unmarshal([]byte(expected[name]), &want) != nil || !reflect.DeepEqual(got, want) {
			return ErrKeyService
		}
	}
	return nil
}

// role is empty for the issuer, which must have its own positive explicit cap.
// For children the exact role was independently checked in this same bounded
// invocation. OpenBao2.7.1 reports zero in lookup when only that role supplied
// the cap; nonrenewability, finite actual expiry and original claim checks remain.
func (s *InitialProviderIssuer) lookup(ctx context.Context, c *bao.Client, policy, role string) (initialTokenLookup, error) {
	r, _, e := initialProviderCall(ctx, c, http.MethodGet, "auth/token/lookup-self", nil)
	var d initialTokenLookup
	if e != nil || !initialProviderFields(r.Data, "accessor", "type", "policies", "num_uses", "orphan", "renewable", "entity_id", "creation_ttl", "explicit_max_ttl", "issue_time", "expire_time") || !initialProviderDecode(r.Data, &d) || !identity.Text(d.Accessor, 128) || d.Type != "service" || d.Orphan || d.Renewable || d.Period != 0 || d.Entity != "" || len(d.IdentityPolicies) != 0 || len(d.Bound) != 0 || d.Uses != 0 || !reflect.DeepEqual(d.Policies, []string{policy}) || d.MaxTTL < 0 || d.MaxTTL > 900 || d.MaxTTL == 0 && (role == "" || d.Role != role || d.Path != "auth/token/create/"+role) || d.CreationTTL < 1 || d.CreationTTL > 900 || d.Issued.IsZero() || d.Expire.IsZero() || !d.Issued.Before(d.Expire) || d.Expire.Sub(d.Issued) > 901*time.Second || d.LastRenewal != 0 || !d.LastRenewalDate.IsZero() || s.now().Before(d.Issued) || !s.now().Before(d.Expire) || ctx.Err() != nil {
		return initialTokenLookup{}, ErrKeyService
	}
	return d, nil
}

// Check verifies the issuer and both role/policy profiles without issuing a
// token. Its original <=5s lease must survive the caller's subsequent CAS/effect.
type initialProviderCheckFailure struct {
	phase string
	cause error
}

func (e initialProviderCheckFailure) Error() string {
	return "initial provider preflight " + e.phase + ": unavailable"
}
func (e initialProviderCheckFailure) Unwrap() error { return e.cause }

// InitialProviderCheckStage returns only a fixed local phase label, never a
// provider response, configured source name, credential or request value.
func InitialProviderCheckStage(err error) string {
	var e initialProviderCheckFailure
	if !errors.As(err, &e) {
		return ""
	}
	switch e.phase {
	case "input", "wrap-role", "unwrap-role", "policies", "issuer-profile", "final-deadline":
		return e.phase
	}
	return ""
}
func (s *InitialProviderIssuer) Check(ctx context.Context, notAfter time.Time) (_ contracts.InitialProviderParent, _ time.Time, err error) {
	phase := "input"
	defer func() {
		if err != nil {
			err = initialProviderCheckFailure{phase, err}
		}
	}()
	var zero contracts.InitialProviderParent
	if s == nil || ctx == nil || notAfter.IsZero() {
		return zero, time.Time{}, ErrKeyService
	}
	until := s.now().Add(5 * time.Second)
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	phase = "wrap-role"
	if e := s.role(ctx, s.profile.WrapRole, s.profile.WrapPolicy); e != nil {
		return zero, time.Time{}, e
	}
	phase = "unwrap-role"
	if e := s.role(ctx, s.profile.UnwrapRole, s.profile.UnwrapPolicy); e != nil {
		return zero, time.Time{}, e
	}
	phase = "policies"
	if e := s.policies(ctx); e != nil {
		return zero, time.Time{}, e
	}
	phase = "issuer-profile"
	d, e := s.lookup(ctx, s.client, s.profile.IssuerPolicy, "")
	if e != nil || d.Expire.After(notAfter) {
		return zero, time.Time{}, ErrKeyService
	}
	phase = "final-deadline"
	if !s.now().Before(until) || ctx.Err() != nil {
		return zero, time.Time{}, ErrKeyService
	}
	until = identity.Earlier(until, d.Expire)
	return contracts.InitialProviderParent{Accessor: d.Accessor, IssuedAt: d.Issued.UTC(), ExpiresAt: d.Expire.UTC()}, until, nil
}
func initialProviderParentEqual(a, b contracts.InitialProviderParent) bool {
	return a.Accessor == b.Accessor && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}
func (s *InitialProviderIssuer) metadata(purpose string, i contracts.InitialProviderIssue) map[string]string {
	return map[string]string{"asservat-installation": s.installation, "asservat-request": s.request, "asservat-operation": i.ID, "asservat-purpose": purpose}
}
func (s *InitialProviderIssuer) validIssue(i contracts.InitialProviderIssue, parent contracts.InitialProviderParent) bool {
	return authorization.UUID(i.ID) && !i.StartedAt.IsZero() && i.StartedAt.Before(i.Until) && i.Until.Sub(i.StartedAt) <= 5*time.Second && i.Until.Before(i.ExpiresBefore) && i.ExpiresBefore.Equal(parent.ExpiresAt)
}
func (s *InitialProviderIssuer) Issue(ctx context.Context, purpose string, i contracts.InitialProviderIssue, parent contracts.InitialProviderParent) (contracts.InitialProviderResponse, error) {
	var zero contracts.InitialProviderResponse
	if s == nil || ctx == nil || !s.validIssue(i, parent) || i.Response != nil {
		return zero, ErrKeyService
	}
	role, policy, ok := s.purpose(purpose)
	if !ok {
		return zero, ErrKeyService
	}
	ctx, end := context.WithDeadline(ctx, i.Until)
	defer end()
	got, until, e := s.Check(ctx, i.ExpiresBefore)
	if e != nil || !initialProviderParentEqual(got, parent) || s.now().Before(i.StartedAt) || !s.now().Before(i.Until) {
		return zero, ErrKeyService
	}
	ctx, done := context.WithDeadline(ctx, until)
	defer done()
	// Derive TTL from the original latest permitted completion, so a slow
	// acknowledged POST inside that same interval cannot slide child expiry.
	seconds := int64(i.ExpiresBefore.Sub(i.Until)/time.Second) - 1
	if seconds < 1 || seconds > 900 {
		return zero, ErrKeyService
	}
	body := map[string]any{"policies": []string{policy}, "meta": s.metadata(purpose, i), "no_parent": false, "no_default_policy": true, "renewable": false, "ttl": strconv.FormatInt(seconds, 10) + "s", "type": "service", "num_uses": 0, "display_name": "asservat-initial-" + purpose}
	r, _, e := initialProviderCall(ctx, s.client, http.MethodPost, "auth/token/create/"+role, body)
	a := r.Auth
	if e != nil || a == nil || !ValidProviderToken([]byte(a.ClientToken)) || len(a.ClientToken) > contracts.InitialProviderTokenMaxBytes || !identity.Text(a.Accessor, 128) || a.Type != "service" || a.Orphan || a.Renewable || a.EntityID != "" || len(a.IdentityPolicies) != 0 || a.MFARequirement != nil || a.Uses != 0 || a.LeaseDuration < 1 || int64(a.LeaseDuration) > seconds || !reflect.DeepEqual(a.Policies, []string{policy}) || !reflect.DeepEqual(a.TokenPolicies, []string{policy}) || !reflect.DeepEqual(a.Metadata, s.metadata(purpose, i)) {
		return zero, ErrKeyService
	}
	c, e := s.client.Clone()
	if e != nil {
		return zero, ErrKeyService
	}
	c.SetToken(a.ClientToken)
	d, e := s.lookup(ctx, c, policy, role)
	if e != nil || d.Accessor != a.Accessor || d.Path != "auth/token/create/"+role || d.Role != role || !reflect.DeepEqual(d.Meta, s.metadata(purpose, i)) || d.Issued.Before(i.StartedAt) || d.Issued.After(i.Until) || d.Expire.After(i.ExpiresBefore) || !s.now().Before(i.Until) || !s.now().Before(until) || ctx.Err() != nil {
		return zero, ErrKeyService
	}
	return contracts.InitialProviderResponse{Token: a.ClientToken, Accessor: a.Accessor, IssuedAt: d.Issued.UTC(), ExpiresAt: d.Expire.UTC()}, nil
}

// Verify rechecks a retained positive response. It never constructs completion
// for a missing response, calls Create, or renews any original provider date.
func (s *InitialProviderIssuer) Verify(ctx context.Context, purpose string, i contracts.InitialProviderIssue, parent contracts.InitialProviderParent, r contracts.InitialProviderResponse) error {
	if s == nil || ctx == nil || !s.validIssue(i, parent) || !ValidProviderToken([]byte(r.Token)) || len(r.Token) > contracts.InitialProviderTokenMaxBytes {
		return ErrKeyService
	}
	role, policy, ok := s.purpose(purpose)
	if !ok {
		return ErrKeyService
	}
	got, until, e := s.Check(ctx, i.ExpiresBefore)
	if e != nil || !initialProviderParentEqual(got, parent) {
		return ErrKeyService
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	c, e := s.client.Clone()
	if e != nil {
		return ErrKeyService
	}
	c.SetToken(r.Token)
	d, e := s.lookup(ctx, c, policy, role)
	if e != nil || d.Accessor != r.Accessor || !d.Issued.Equal(r.IssuedAt) || !d.Expire.Equal(r.ExpiresAt) || d.Issued.Before(i.StartedAt) || d.Issued.After(i.Until) || d.Expire.After(i.ExpiresBefore) || d.Path != "auth/token/create/"+role || d.Role != role || !reflect.DeepEqual(d.Meta, s.metadata(purpose, i)) || !s.now().Before(until) || ctx.Err() != nil {
		return ErrKeyService
	}
	return nil
}
