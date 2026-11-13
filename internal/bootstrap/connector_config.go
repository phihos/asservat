package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// regionalConfig is the connector's resolved startup input: the Helm config,
// the hub's public regional offer and the browser-issued cluster binding.
type regionalConfig struct {
	contracts.ConnectorConfig
	offer   contracts.RegionalOffer
	binding value.PeerBinding
	// executor is set when the offer names the regional executor and the
	// config enables it; owners and keys are the offer's, with combined-mode
	// in-cluster addresses applied.
	executor bool
	hub      contracts.RegionalHubEndpoint
	owners   contracts.RegionalContextOwners
	keys     contracts.RegionalWrapService
	store    contracts.RegionalEvidenceStore
}

func (c regionalConfig) rootID() string { return c.offer.PermissionRootID }

// readConnectorConfig decodes config.json and checks every Helm-supplied
// name and identifier. The offer is resolved separately.
func readConnectorConfig(ctx context.Context, in *providerInputs) (contracts.ConnectorConfig, error) {
	var zero contracts.ConnectorConfig
	b, err := in.read(ctx, contracts.ConnectorConfigFile, contracts.ConnectorConfigMaxBytes)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeConnectorConfig(bytes.NewReader(b))
	if err != nil || validConnectorConfig(c) != nil {
		return zero, mounts.ErrUnavailable
	}
	return c, nil
}

func validConnectorConfig(c contracts.ConnectorConfig) error {
	bad := func(step string) error { return &fixedStepError{"config/" + step, mounts.ErrUnavailable} }
	if c.Format != contracts.ConnectorConfigFormat {
		return bad("format")
	}
	switch c.Mode {
	case contracts.ConnectorModeCluster:
		if c.Offer == nil || c.Hub != nil || c.OfferConfigMap != "" {
			return bad("cluster-offer")
		}
	case contracts.ConnectorModeCombined:
		if c.Offer != nil || len(validation.IsDNS1123Subdomain(c.OfferConfigMap)) != 0 || c.Hub == nil || !ownerEndpoint(c.Hub.Federation) || c.Hub.Owners != "" && !ownerDialAddress(c.Hub.Owners) || c.Hub.KeyService != "" && !ownerEndpoint(c.Hub.KeyService) {
			return bad("combined-hub")
		}
	default:
		return bad("mode")
	}
	if !authorization.UUID(c.ClusterID) || !authorization.UUID(c.PeerID) || len(validation.IsDNS1123Label(c.Namespace)) != 0 {
		return bad("binding")
	}
	for _, name := range []string{c.Deployment, c.ServiceAccount, c.ClusterCredential} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return bad("names")
		}
	}
	if d, err := hex.DecodeString(c.ImageDigest); err != nil || len(d) != 32 || hex.EncodeToString(d) != c.ImageDigest {
		return bad("image")
	}
	if x := c.Executor; x != nil {
		if len(validation.IsDNS1123Subdomain(x.CapacityAccount)) != 0 || x.CapacityAccount == c.ServiceAccount || x.CapacityAudience != "" && !identity.Text(x.CapacityAudience, 512) || x.Concurrency < 1 || x.Concurrency > 16 ||
			x.Alertmanager != "" && !kube.AlertmanagerURL(x.Alertmanager) || !kube.IdentityMappingsValid(x.IdentityMappings) || !kube.ProfileEndpointsValid(x.ProfileEndpoints) {
			return bad("executor")
		}
	}
	if n := c.Collector; n != nil {
		if len(validation.IsDNS1123Label(n.Namespace)) != 0 || n.Namespace == c.Namespace || len(validation.IsDNS1123Subdomain(n.DaemonSet)) != 0 || len(validation.IsDNS1123Subdomain(n.ServiceAccount)) != 0 ||
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

// resolveRegionalConfig completes c with the hub's offer. Cluster mode uses
// the offer from values. Combined mode reads the hub's published offer
// ConfigMap in the shared release namespace (get on that one name).
func resolveRegionalConfig(ctx context.Context, in *providerInputs, c contracts.ConnectorConfig) (regionalConfig, error) {
	out := regionalConfig{ConnectorConfig: c}
	if c.Mode == contracts.ConnectorModeCluster {
		out.offer = *c.Offer
	} else {
		offer, err := readCombinedOffer(ctx, in, c.Namespace, c.OfferConfigMap)
		if err != nil {
			return out, &fixedStepError{"offer", err}
		}
		out.offer = offer
	}
	o := out.offer
	if o.Format != contracts.RegionalOfferFormat || !authorization.UUID(o.InstallationID) || !authorization.UUID(o.PermissionRootID) || !authorization.UUID(o.IssuerEpoch) || len(o.ConnectorIssuerRoots) == 0 || len(o.ConnectorBacking) == 0 {
		return out, &fixedStepError{"offer", mounts.ErrUnavailable}
	}
	out.binding = value.PeerBinding{InstallationID: o.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: o.IssuerEpoch, PeerID: c.PeerID, Role: value.ConnectorPeer}
	out.hub = o.Federation
	if c.Hub != nil {
		out.hub.Endpoint = c.Hub.Federation
	}
	if !out.binding.Valid() || !ownerEndpoint(out.hub.Endpoint) || !identity.Text(out.hub.ServerName, 253) {
		return out, &fixedStepError{"offer-binding", mounts.ErrUnavailable}
	}
	offered, err := o.RegionalExecutorOffered()
	if err != nil {
		return out, &fixedStepError{"offer-executor", mounts.ErrUnavailable}
	}
	if c.Executor == nil || !offered {
		return out, nil
	}
	out.executor = true
	out.owners, out.keys, out.store = *o.Owners, *o.KeyService, *o.EvidenceStore
	if c.Hub != nil && c.Hub.Owners != "" {
		out.owners.Address = c.Hub.Owners
	}
	if c.Hub != nil && c.Hub.KeyService != "" {
		out.keys.Endpoint = c.Hub.KeyService
	}
	s, k := out.store, out.keys
	if !ownerEndpoint(s.Endpoint) || !identity.Text(s.Region, 128) || !identity.Text(s.Bucket, 63) || !authorization.UUID(s.StoreID) || !ownerEndpoint(k.Endpoint) ||
		!(authorization.KeyScope{InstallationID: o.InstallationID, Purpose: "artifact", KeyID: k.KeyID}).Valid() || !ownerDialAddress(out.owners.Address) || o.WorkKey == nil {
		return out, &fixedStepError{"offer-executor", mounts.ErrUnavailable}
	}
	return out, nil
}

func readCombinedOffer(ctx context.Context, in *providerInputs, namespace, name string) (contracts.RegionalOffer, error) {
	var zero contracts.RegionalOffer
	api, err := kubernetes.NewForConfig(in.kubernetes(contracts.ConnectorKubeTokenFile))
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var object *core.ConfigMap
	if object, err = api.CoreV1().ConfigMaps(namespace).Get(call, name, meta.GetOptions{}); err != nil {
		return zero, mounts.ErrUnavailable
	}
	raw := object.Data[contracts.RegionalOfferFile]
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	var offer contracts.RegionalOffer
	if len(raw) > 1<<20 || d.Decode(&offer) != nil || d.More() {
		return zero, mounts.ErrUnavailable
	}
	return offer, nil
}

// connectorDeployment is the identity document's workload section.
func (c regionalConfig) connectorDeployment() contracts.ConnectorDeployment {
	return contracts.ConnectorDeployment{Namespace: c.Namespace, ServiceAccount: c.ServiceAccount, Deployment: c.Deployment, ServingSlots: contracts.RegionalServingSlots, RetainedProcesses: contracts.RegionalRetainedProcesses}
}
