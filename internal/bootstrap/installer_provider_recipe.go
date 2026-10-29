package bootstrap

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// RunInstallerProviderRecipe writes deterministic public provider prerequisites.
// It does not connect to a service or create/replace a key. Optional history
// inputs read the existing bootstrap envelope but never emit its credential.
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
	historyOffer := flags.String("history-offer", "", "optional regional-offer.json for history capability proposal")
	historyBootstrap := flags.String("history-bootstrap", "", "existing bootstrap record supplying the exact regional cluster identity; never included in output")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return mounts.ErrUnavailable
	}
	history, err := installerHistoryCapability(*historyOffer, *historyBootstrap)
	if err != nil {
		return err
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
		Format       string                                 `json:"format"`
		TransitMount string                                 `json:"transit_mount"`
		TransitKey   string                                 `json:"transit_key"`
		KeyType      string                                 `json:"key_type"`
		Policies     map[string]string                      `json:"policies"`
		Roles        map[string]role                        `json:"token_roles"`
		Issuer       issuerToken                            `json:"issuer_token_request"`
		History      *objectstore.RegionalHistoryCapability `json:"regionalHistory,omitempty"`
	}{"asservat-bootstrap-provider-recipe/v1", *mount, *key, "aes256-gcm96", policies,
		map[string]role{*wrapRole: {[]string{*wrapPolicy}, false, false, "service", true, 900}, *unwrapRole: {[]string{*unwrapPolicy}, false, false, "service", true, 900}},
		issuerToken{[]string{*issuer}, true, false, false, "service", "15m", "15m"}, history}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	return ctx.Err()
}

// The existing provider-prerequisite output supplies this proposal. It does not
// issue a credential or establish that an external provider accepted the policy.
func installerHistoryCapability(offerPath, bootstrapPath string) (*objectstore.RegionalHistoryCapability, error) {
	if offerPath == "" && bootstrapPath == "" {
		return nil, nil
	}
	if offerPath == "" || bootstrapPath == "" {
		return nil, mounts.ErrUnavailable
	}
	offerRaw, err := os.ReadFile(offerPath)
	if err != nil || len(offerRaw) > 1<<20 {
		return nil, mounts.ErrUnavailable
	}
	var offer contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader(offerRaw))
	d.DisallowUnknownFields()
	if d.Decode(&offer) != nil || d.Decode(new(any)) != io.EOF || offer.Format != contracts.RegionalOfferFormat || offer.EvidenceStore == nil {
		return nil, mounts.ErrUnavailable
	}
	raw, err := os.ReadFile(bootstrapPath)
	if err != nil || len(raw) > 128<<10 {
		clear(raw)
		return nil, mounts.ErrUnavailable
	}
	defer clear(raw)
	envelope, err := kms.DecodeBootstrapRecord(raw)
	if err != nil || !envelope.Valid() || envelope.Binding.InstallationID != offer.InstallationID || envelope.Binding.IssuerEpoch != offer.IssuerEpoch {
		return nil, mounts.ErrUnavailable
	}
	capability, err := objectstore.SeaweedHistoryCapability(offer.EvidenceStore.Bucket, offer.PermissionRootID, envelope.Binding.ClusterID)
	if err != nil {
		return nil, err
	}
	return &capability, nil
}
