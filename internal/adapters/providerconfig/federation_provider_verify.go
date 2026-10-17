package providerconfig

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// VerifyFederation reads back the federation's applied provider setup through
// the inspection token (ADR-193): the shared auth mount, the audit key, each
// role and policy exactly, the connector PKI issuer against the operator's
// connector roots and both connector PKI roles exactly. It returns the end of
// this observation; it confers no authority to use any role.
func (r *SetupReader) VerifyFederation(ctx context.Context, in contracts.FederationDeployment, connectorRoots [][]byte) (time.Time, error) {
	setup, err := FederationProviderSetupFor(in)
	if err != nil {
		return time.Time{}, ErrSetupUnavailable
	}
	p := setup.Authentication.Profile
	k := in.KeyService
	o, err := r.begin(ctx, contracts.OwnerProviderEndpoint{Endpoint: k.Endpoint, Roots: k.Roots}, federationSetupPaths(in, setup))
	if err != nil {
		return time.Time{}, err
	}
	defer o.finish()
	issuerUntil := o.until
	checks := []setupReadCheck{
		{"sys/mounts/auth/" + p.AuthMount, "federation authentication mount", func(d map[string]json.RawMessage) error { return verifyAuthMount(d, p.AuthMountAccessor) }},
		{"sys/mounts/" + k.AuditMount, "federation audit engine", verifyTransitMount},
		{k.AuditMount + "/keys/" + k.AuditKey, "federation audit key", func(d map[string]json.RawMessage) error { return verifyTransitKey(d, k.AuditKey) }},
	}
	for _, role := range setup.Authentication.Roles {
		checks = append(checks,
			setupReadCheck{"auth/" + p.AuthMount + "/role/" + role.Name, "federation " + role.Purpose + " role", func(d map[string]json.RawMessage) error { return verifyKubernetesRole(d, role.Role) }},
			setupReadCheck{"sys/policies/acl/" + role.Name, "federation " + role.Purpose + " policy", func(d map[string]json.RawMessage) error { return verifyACL(d, role.Name, role.Policy) }})
	}
	checks = append(checks,
		setupReadCheck{"sys/mounts/" + k.PKIMount, "connector certificate engine", func(d map[string]json.RawMessage) error {
			if !setupIs(d, "type", "pki") {
				return ErrSetupUnavailable
			}
			return nil
		}},
		setupReadCheck{k.PKIMount + "/cert/ca", "connector certificate issuer", func(d map[string]json.RawMessage) error {
			end, e := verifySetupIssuer(d, connectorRoots, time.Now())
			if e != nil {
				return e
			}
			issuerUntil = identity.Earlier(issuerUntil, end)
			return nil
		}})
	for i, role := range setup.PKIRoles {
		component := "connector client certificate role"
		if i == 1 {
			component = "connector server certificate role"
		}
		checks = append(checks, setupReadCheck{k.PKIMount + "/roles/" + role.Name, component, func(d map[string]json.RawMessage) error { return verifySetupPKIRole(d, role.Role) }})
	}
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
	for _, anchors := range [][][]byte{k.Roots, connectorRoots} {
		_, end, e := mtls.OwnerTrustRoots(anchors, time.Now())
		if e != nil {
			return time.Time{}, ErrSetupUnavailable
		}
		until = identity.Earlier(until, end)
	}
	return until, nil
}
