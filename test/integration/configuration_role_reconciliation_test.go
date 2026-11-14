package integration

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func configurationRoleSQLConfiguration(in contracts.ConfigurationRuntimeRoles, issuer string) fleet.OwnerConfiguration {
	return fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: issuer, Namespace: in.Namespace.Name, NamespaceUID: in.Namespace.UID, Service: "hub", ServiceUID: custodyID(), Deployment: "hub", DeploymentUID: custodyID(), ServiceAccount: "hub", AccountUID: custodyID(), Port: 8443}, Revision: identity.Revision{UID: in.OwnerSource.UID, Generation: 1, Digest: artifact.Digest{4}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{[]byte("synthetic public CA input; no TLS authentication exercised")}}
}
