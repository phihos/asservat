package providerconfig

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// VerifyPublisher reads back the publisher's applied provider setup through
// the inspection token (ADR-203): the shared auth mount, its audit Transit
// key, each role and policy exactly, the worker PKI issuer against
// workerRoots and the verifier PKI role exactly. The publisher input must pin
// the same worker roots as its verifier issuer. It returns the end of this
// observation; it confers no authority to use any role.
func (r *SetupReader) VerifyPublisher(ctx context.Context, in contracts.PublisherDeployment, workerRoots [][]byte) (time.Time, error) {
	setup, err := PublisherProviderSetupFor(in)
	endpoint, _ := publisherProviderEndpoint(in)
	// Equal endpoints compare the two root lists byte for byte.
	if err != nil || len(workerRoots) < 1 || !sameSetupEndpoint(contracts.OwnerProviderEndpoint{Roots: in.Verifier.IssuerRoots}, contracts.OwnerProviderEndpoint{Roots: workerRoots}) {
		return time.Time{}, ErrSetupUnavailable
	}
	p, a, v := setup.Authentication.Profile, in.AuditKeys, in.Verifier
	o, err := r.begin(ctx, endpoint, publisherSetupPaths(in, setup))
	if err != nil {
		return time.Time{}, err
	}
	defer o.finish()
	issuerUntil := o.until
	checks := []setupReadCheck{
		{"sys/mounts/auth/" + p.AuthMount, "publisher authentication mount", func(d map[string]json.RawMessage) error { return verifyAuthMount(d, p.AuthMountAccessor) }},
		{"sys/mounts/" + a.Mount, "publisher audit engine", verifyTransitMount},
		{a.Mount + "/keys/" + a.Key, "publisher audit key", func(d map[string]json.RawMessage) error { return verifyTransitKey(d, a.Key) }},
	}
	for _, role := range setup.Authentication.Roles {
		checks = append(checks,
			setupReadCheck{"auth/" + p.AuthMount + "/role/" + role.Name, "publisher " + role.Purpose + " role", func(d map[string]json.RawMessage) error { return verifyKubernetesRole(d, role.Role) }},
			setupReadCheck{"sys/policies/acl/" + role.Name, "publisher " + role.Purpose + " policy", func(d map[string]json.RawMessage) error { return verifyACL(d, role.Name, role.Policy) }})
	}
	checks = append(checks,
		setupReadCheck{"sys/mounts/" + v.PKIMount, "worker certificate engine", func(d map[string]json.RawMessage) error {
			if !setupIs(d, "type", "pki") {
				return ErrSetupUnavailable
			}
			return nil
		}},
		setupReadCheck{v.PKIMount + "/cert/ca", "worker certificate issuer", func(d map[string]json.RawMessage) error {
			end, e := verifySetupIssuer(d, workerRoots, time.Now())
			if e != nil {
				return e
			}
			issuerUntil = identity.Earlier(issuerUntil, end)
			return nil
		}},
		setupReadCheck{v.PKIMount + "/roles/" + v.Role, "verifier certificate role", func(d map[string]json.RawMessage) error { return verifySetupPKIRole(d, setup.PKIRole.Role) }})
	for _, check := range checks {
		data, e := o.get(check.path)
		if e != nil || check.verify(data) != nil {
			return time.Time{}, setupComponentError(check.component)
		}
	}
	if !o.valid() {
		return time.Time{}, ErrSetupUnavailable
	}
	until := identity.Earlier(o.until, issuerUntil)
	for _, anchors := range [][][]byte{endpoint.Roots, workerRoots} {
		_, end, e := mtls.OwnerTrustRoots(anchors, time.Now())
		if e != nil {
			return time.Time{}, ErrSetupUnavailable
		}
		until = identity.Earlier(until, end)
	}
	return until, nil
}
