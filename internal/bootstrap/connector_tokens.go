package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"

	"asservat.local/asservat/internal/adapters/mounts"
	oidcadapter "asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
)

// connectorTokens verifies connector ServiceAccount tokens (ADR-334): the
// hub's own cluster through its API server's issuer discovery, every
// registered workload cluster through its issuer or static JWKS. The
// federation, the hub-api and the key service each hold one.
type connectorTokens struct {
	verifier *oidcadapter.ServiceAccountVerifier
	ids      contracts.ServiceIDs
	process  string
}

func newConnectorTokens(c contracts.ConnectorTokens, ids contracts.ServiceIDs, process string) (connectorTokens, error) {
	return newConnectorTokensFor(c, ids, process, serviceKubernetes)
}

// newConnectorTokensFor discovers the hub cluster's issuer through local,
// the process's own API client configuration.
func newConnectorTokensFor(c contracts.ConnectorTokens, ids contracts.ServiceIDs, process string, local func() (*rest.Config, error)) (connectorTokens, error) {
	var clusters []oidcadapter.ServiceAccountCluster
	split := func(connector string) (string, string, bool) {
		ns, account, ok := strings.Cut(connector, "/")
		return ns, account, ok && ns != "" && account != ""
	}
	if c.LocalConnector != "" {
		config, err := local()
		if err != nil {
			return connectorTokens{}, &fixedStepError{"tokens/kubernetes", mounts.ErrUnavailable}
		}
		client, err := rest.HTTPClientFor(config)
		ns, account, ok := split(c.LocalConnector)
		if err != nil || !ok {
			return connectorTokens{}, &fixedStepError{"tokens/local", mounts.ErrUnavailable}
		}
		clusters = append(clusters, oidcadapter.ServiceAccountCluster{ClusterID: ids.ClusterID, PeerID: ids.PeerID, Discovery: config.Host, Namespace: ns, Account: account, Client: client})
	}
	for _, r := range c.Clusters {
		peer, ok := contracts.RemotePeerID(ids.InstallationID, r.ClusterID)
		ns, account, valid := split(r.Connector)
		if !ok || !valid || r.ClusterID == ids.ClusterID {
			return connectorTokens{}, &fixedStepError{"tokens/cluster", configuration.ErrInvalid}
		}
		clusters = append(clusters, oidcadapter.ServiceAccountCluster{ClusterID: r.ClusterID, PeerID: peer, Issuer: r.Issuer, JWKS: []byte(r.JWKS), Namespace: ns, Account: account})
	}
	v, err := oidcadapter.NewServiceAccountVerifier(c.Audiences, clusters)
	if err != nil {
		return connectorTokens{}, &fixedStepError{"tokens", configuration.ErrInvalid}
	}
	return connectorTokens{v, ids, process}, nil
}

func (t connectorTokens) VerifyConnector(ctx context.Context, token string) (value.ConnectorCluster, error) {
	c, _, err := t.VerifyConnectorUntil(ctx, token)
	return c, err
}

// VerifyConnectorUntil also returns the token's expiry.
func (t connectorTokens) VerifyConnectorUntil(ctx context.Context, token string) (value.ConnectorCluster, time.Time, error) {
	c, until, err := t.verifier.VerifyConnectorToken(ctx, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, t.process+" connector token refused")
		return value.ConnectorCluster{}, time.Time{}, value.ErrDenied
	}
	return value.ConnectorCluster{RootID: t.ids.PermissionRootID, PeerID: c.PeerID, InstallationID: t.ids.InstallationID, ClusterID: c.ClusterID}, until, nil
}
