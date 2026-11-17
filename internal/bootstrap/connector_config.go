package bootstrap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

// regionalConfig is the connector's resolved startup input: the Helm config
// and the settings the hub sends on connect.
type regionalConfig struct {
	contracts.ConnectorConfig
	ClusterID, PeerID string
	offer             contracts.RegionalOffer
	binding           value.PeerBinding
	// executor is set when the config enables the regional executor;
	// owners, keys and store are the offer's, and evidence and history the
	// cluster's object-store capabilities.
	executor          bool
	owners            contracts.RegionalContextOwners
	keys              contracts.RegionalWrapService
	store             contracts.RegionalEvidenceStore
	evidence, history contracts.OwnerStorageCredential
}

func (c regionalConfig) rootID() string { return c.offer.PermissionRootID }

// readConnectorConfig decodes config.json and checks every Helm-supplied
// name and identifier.
func readConnectorConfig(ctx context.Context, in *providerInputs) (contracts.ConnectorConfig, error) {
	var zero contracts.ConnectorConfig
	b, err := in.read(ctx, contracts.ConnectorConfigFile, contracts.ConnectorConfigMaxBytes)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeConnectorConfig(bytes.NewReader(b))
	if err != nil || validConnectorConfig(c) != nil {
		// Helm-rendered values do not heal by waiting.
		return zero, &fixedStepError{"config", cfg.ErrInvalid}
	}
	return c, nil
}

func validConnectorConfig(c contracts.ConnectorConfig) error {
	bad := func(step string) error { return &fixedStepError{"config/" + step, mounts.ErrUnavailable} }
	if c.Format != contracts.ConnectorConfigFormat {
		return bad("format")
	}
	if c.Mode != contracts.ConnectorModeCluster && c.Mode != contracts.ConnectorModeCombined {
		return bad("mode")
	}
	if u, err := url.Parse(c.Hub); err != nil || u.Scheme != "https" || u.Host == "" || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil {
		return bad("hub")
	}
	if len(validation.IsDNS1123Label(c.Namespace)) != 0 {
		return bad("namespace")
	}
	for _, name := range []string{c.Deployment, c.ServiceAccount} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return bad("names")
		}
	}
	if d, err := hex.DecodeString(c.ImageDigest); err != nil || len(d) != 32 || hex.EncodeToString(d) != c.ImageDigest {
		return bad("image")
	}
	if x := c.Executor; x != nil {
		if x.Concurrency < 1 || x.Concurrency > 16 ||
			x.Alertmanager != "" && !kube.AlertmanagerURL(x.Alertmanager) || !kube.IdentityMappingsValid(x.IdentityMappings) || !kube.ProfileEndpointsValid(x.ProfileEndpoints) {
			return bad("executor")
		}
	}
	if n := c.Collector; n != nil {
		if len(validation.IsDNS1123Label(n.Namespace)) != 0 || n.Namespace == c.Namespace || len(validation.IsDNS1123Subdomain(n.ServiceAccount)) != 0 ||
			len(validation.IsDNS1123Subdomain(n.ListenerSecret)) != 0 || len(validation.IsDNS1123Subdomain(n.RootConfigMap)) != 0 || len(validation.IsDNS1123Subdomain(n.ServerName)) != 0 {
			return bad("collector")
		}
	}
	return nil
}

// kubernetesRoots reads the projected kube-root-ca.crt bundle.
func kubernetesRoots(ctx context.Context, in *providerInputs) ([][]byte, error) {
	b, err := in.read(ctx, contracts.ConnectorKubeRootsFile, 64<<10)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	var roots [][]byte
	for rest := b; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			roots = append(roots, block.Bytes)
		}
	}
	if len(roots) == 0 || len(roots) > 16 {
		return nil, mounts.ErrUnavailable
	}
	return roots, nil
}

// hubRoots reads the hub CA bundle; an empty one selects the system roots.
func hubRoots(ctx context.Context, in *providerInputs) (*x509.CertPool, error) {
	b, err := in.read(ctx, contracts.ConnectorHubRootsFile, 64<<10)
	if err != nil {
		return nil, &fixedStepError{"hub-roots", mounts.ErrUnavailable}
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, &fixedStepError{"hub-roots", cfg.ErrInvalid}
	}
	return pool, nil
}

// readHubSettings asks the hub for this cluster's settings (REQ-FED-001) and
// completes c with them.
func readHubSettings(ctx context.Context, channel *connectorlifecycle.Client, c contracts.ConnectorConfig) (regionalConfig, error) {
	out := regionalConfig{ConnectorConfig: c}
	frame, err := channel.Run(ctx, connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeSettings, OperationID: uuid.NewString()}, nil)
	if err != nil || frame.Kind != "result" || frame.Settings == nil {
		return out, &fixedStepError{"hub-settings", errors.Join(mounts.ErrUnavailable, errRegionalChannel)}
	}
	s := *frame.Settings
	o := s.Offer
	if o.Format != contracts.RegionalOfferFormat || !authorization.UUID(o.InstallationID) || !authorization.UUID(o.PermissionRootID) || !authorization.UUID(o.IssuerEpoch) || s.ClusterID == s.PeerID {
		return out, &fixedStepError{"hub-settings/fields", mounts.ErrUnavailable}
	}
	out.ClusterID, out.PeerID, out.offer = s.ClusterID, s.PeerID, o
	out.binding = value.PeerBinding{InstallationID: o.InstallationID, ClusterID: s.ClusterID, IssuerEpoch: o.IssuerEpoch, PeerID: s.PeerID, Role: value.ConnectorPeer}
	if !out.binding.Valid() {
		return out, &fixedStepError{"hub-settings/binding", mounts.ErrUnavailable}
	}
	if c.Executor == nil {
		return out, nil
	}
	if !o.Complete() {
		return out, &fixedStepError{"hub-settings/offer", mounts.ErrUnavailable}
	}
	out.executor = true
	out.owners, out.keys, out.store = *o.Owners, *o.KeyService, *o.EvidenceStore
	out.evidence, out.history = s.Evidence, s.History
	st, k := out.store, out.keys
	if !ownerEndpoint(st.Endpoint) || !identity.Text(st.Region, 128) || !identity.Text(st.Bucket, 63) || !authorization.UUID(st.StoreID) || !ownerEndpoint(k.Endpoint) ||
		!(authorization.KeyScope{InstallationID: o.InstallationID, Purpose: "artifact", KeyID: k.KeyID}).Valid() || !ownerDialAddress(out.owners.Address) {
		return out, &fixedStepError{"hub-settings/executor", mounts.ErrUnavailable}
	}
	for _, x := range []contracts.OwnerStorageCredential{out.evidence, out.history} {
		if !identity.Text(x.AccessKeyID, 256) || !identity.Text(x.SecretAccessKey, 4096) || (x.SessionToken != "" && !identity.Text(x.SessionToken, 16384)) {
			return out, &fixedStepError{"hub-settings/storage", mounts.ErrUnavailable}
		}
	}
	return out, nil
}
