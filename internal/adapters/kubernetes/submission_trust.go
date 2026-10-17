package kubernetes

import (
	"context"
	"encoding/base64"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type SubmissionTrustClient struct {
	client                               *PermissionClient
	name, uid, root, installation, epoch string
}

var _ app.SubmissionTrustReader = (*SubmissionTrustClient)(nil)

func NewSubmissionTrustClient(client *PermissionClient, name, uid, root, installation, epoch string) (*SubmissionTrustClient, error) {
	if client == nil || !installationRefValid(name, uid) || !authorization.UUID(root) || !authorization.UUID(installation) || !authorization.UUID(epoch) {
		return nil, value.ErrInvalid
	}
	return &SubmissionTrustClient{client, name, uid, root, installation, epoch}, nil
}
func (c *SubmissionTrustClient) SubmissionTrust(ctx context.Context) (value.SubmissionTrust, error) {
	var zero value.SubmissionTrust
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := c.client.now()
	data, ref, e := c.client.installationConfig(ctx, c.name, c.uid)
	if e != nil || len(data) != 1 || data["submission.json"] == "" {
		return zero, value.ErrUnavailable
	}
	var wire contracts.SubmissionTrust
	digest, e := decodePermissionSpec([]byte(data["submission.json"]), c.client.validator.submissionSchema, &wire)
	if e != nil || wire.RootID != c.root || wire.InstallationID != c.installation || wire.IssuerEpoch != c.epoch {
		return zero, value.ErrUnavailable
	}
	out := value.SubmissionTrust{RootID: wire.RootID, InstallationID: wire.InstallationID, IssuerEpoch: wire.IssuerEpoch, Revision: identity.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, ObservedAt: started, FreshUntil: started.Add(5 * time.Second)}
	for _, k := range wire.Keys {
		pub, e := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(pub) != 32 || base64.StdEncoding.EncodeToString(pub) != k.PublicKey {
			return zero, value.ErrUnavailable
		}
		out.Keys = append(out.Keys, value.SubmissionKey{ID: k.ID, PublicKey: pub, NotBefore: k.NotBefore, NotAfter: k.NotAfter})
	}
	if c.client.current(ctx, started, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
