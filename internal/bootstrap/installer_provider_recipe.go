package bootstrap

import (
	"context"
	"encoding/json"
	"flag"
	"io"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// RunInstallerProviderRecipe writes deterministic public provider prerequisites.
// It does not connect to a service, read credentials or create/replace a key.
// Existing upstream keys, policies and roles must be reviewed independently.
func RunInstallerProviderRecipe(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return mounts.ErrUnavailable
	}
	flags := flag.NewFlagSet("installer-provider-recipe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mount := flags.String("audit-mount", "asservat-audit", "original transit mount")
	key := flags.String("audit-key", "audit", "original transit key")
	issuer := flags.String("issuer-policy", "asservat-install-issuer", "dedicated finite issuer policy")
	wrapRole := flags.String("wrap-role", "asservat-install-wrap", "dedicated wrapping token role")
	wrapPolicy := flags.String("wrap-policy", "asservat-install-encrypt", "dedicated wrapping policy")
	unwrapRole := flags.String("unwrap-role", "asservat-install-unwrap", "dedicated independent acknowledgement role")
	unwrapPolicy := flags.String("unwrap-policy", "asservat-install-decrypt", "dedicated independent acknowledgement policy")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return mounts.ErrUnavailable
	}
	policies, err := kms.InitialBootstrapProviderPolicies(contracts.InitialBootstrapProviders{IssuerPolicy: *issuer, WrapRole: *wrapRole, WrapPolicy: *wrapPolicy, UnwrapRole: *unwrapRole, UnwrapPolicy: *unwrapPolicy}, *mount, *key)
	if err != nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	type role struct {
		AllowedPolicies []string `json:"allowed_policies"`
		Orphan          bool     `json:"orphan"`
		Renewable       bool     `json:"renewable"`
		TokenType       string   `json:"token_type"`
		NoDefault       bool     `json:"token_no_default_policy"`
		MaxTTL          int      `json:"token_explicit_max_ttl"`
	}
	type issuerToken struct {
		Policies  []string `json:"policies"`
		NoDefault bool     `json:"no_default_policy"`
		NoParent  bool     `json:"no_parent"`
		Renewable bool     `json:"renewable"`
		Type      string   `json:"type"`
		TTL       string   `json:"ttl"`
		MaxTTL    string   `json:"explicit_max_ttl"`
	}
	v := struct {
		Format       string            `json:"format"`
		TransitMount string            `json:"transit_mount"`
		TransitKey   string            `json:"transit_key"`
		KeyType      string            `json:"key_type"`
		Policies     map[string]string `json:"policies"`
		Roles        map[string]role   `json:"token_roles"`
		Issuer       issuerToken       `json:"issuer_token_request"`
	}{"asservat-bootstrap-provider-recipe/v1", *mount, *key, "aes256-gcm96", policies,
		map[string]role{*wrapRole: {[]string{*wrapPolicy}, false, false, "service", true, 900}, *unwrapRole: {[]string{*unwrapPolicy}, false, false, "service", true, 900}},
		issuerToken{[]string{*issuer}, true, false, false, "service", "15m", "15m"}}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	return ctx.Err()
}
