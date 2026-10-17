package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"testing"
)

func TestOwnerConfigurationAuditExactPurposeAndSnapshot(t *testing.T) {
	id := testBinding.ClusterID
	c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{[]byte("synthetic-public-root")}}
	k := keys(t)
	ctx := context.Background()
	b, err := SealOwnerConfiguration(ctx, k, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("IssuerRoots")) || bytes.Contains(b, c.IssuerRoots[0]) {
		t.Fatal("clear configuration in audit")
	}
	if err = VerifyOwnerConfiguration(ctx, k, c, b); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"root", "issuer", "revision", "source", "protection", "suspend", "tamper", "format"} {
		t.Run(mode, func(t *testing.T) {
			changed := c.Clone()
			raw := bytes.Clone(b)
			switch mode {
			case "root":
				changed.IssuerRoots[0][0] ^= 1
			case "issuer":
				changed.Pool.IssuerEpoch = "22222222-2222-4222-8222-222222222222"
			case "revision":
				changed.Revision.Generation++
			case "source":
				changed.Revision.UID = "22222222-2222-4222-8222-222222222222"
			case "protection":
				changed.ProtectionDigest[0]++
			case "suspend":
				changed.Suspended = true
			case "tamper":
				raw[len(raw)/2] ^= 1
			case "format":
				raw = bytes.ReplaceAll(raw, []byte("asservat-hub-owner-configuration-audit/v1"), []byte("asservat-download-worker-configuration/v1"))
			}
			if VerifyOwnerConfiguration(ctx, k, changed, raw) == nil {
				t.Fatal("foreign audit accepted")
			}
		})
	}
}
