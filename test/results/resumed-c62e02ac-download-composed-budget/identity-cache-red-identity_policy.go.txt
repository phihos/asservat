package kubernetes

import (
	"context"
	"net/url"
	"time"

	port "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/identity"
)

// IdentityPolicyClient reads installation settings whose protection and provider
// qualification are established by role bootstrap. An issuer from a token can
// only match the pinned issuer; it cannot choose an object, URL or trust profile.
type IdentityPolicyClient struct {
	client            *PermissionClient
	name, uid, issuer string
}

var _ port.PolicyReader = (*IdentityPolicyClient)(nil)

func NewIdentityPolicyClient(client *PermissionClient, name, uid, issuer string) (*IdentityPolicyClient, error) {
	u, err := url.Parse(issuer)
	if client == nil || !installationRefValid(name, uid) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !value.Text(issuer, 2048) {
		return nil, value.ErrInvalid
	}
	return &IdentityPolicyClient{client, name, uid, issuer}, nil
}
func (c *IdentityPolicyClient) IdentityPolicy(ctx context.Context, issuer string) (value.Policy, error) {
	var out value.Policy
	if issuer != c.issuer {
		return out, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil || len(data) != 1 || data["identity.json"] == "" {
		return out, value.ErrUnavailable
	}
	var wire contracts.IdentitySettings
	digest, err := decodePermissionSpec([]byte(data["identity.json"]), c.client.validator.identitySchema, &wire)
	if err != nil || wire.Issuer != issuer {
		return out, value.ErrUnavailable
	}
	out = value.Policy{Revision: value.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, Issuer: wire.Issuer, ObservedAt: start, FreshUntil: start.Add(30 * time.Second), EligibleGroups: wire.EligibleGroups, GroupsAtIssueQualified: wire.GroupsAtIssueQualified, GroupMaxAge: time.Duration(wire.GroupMaxAgeSeconds) * time.Second}
	for _, v := range wire.Clients {
		out.Clients = append(out.Clients, value.Client{ID: v.ID, Kind: value.Kind(v.Kind), ClassQualified: v.ClassQualified})
	}
	for _, v := range wire.EligibleSubjects {
		out.EligibleSubjects = append(out.EligibleSubjects, value.Subject{ID: v.ID, Kind: value.Kind(v.Kind)})
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || out.Validate(c.client.now()) != nil {
		return value.Policy{}, value.ErrUnavailable
	}
	return out, nil
}
