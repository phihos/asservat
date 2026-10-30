package authorization

import (
	"bytes"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
)

// This transient value is checked unit-conversion metadata, not an authority,
// persisted state or wire token. Application code verifies the accepted scope's
// SHA-256 and compiled semantics before binding it. Exact byte/value comparisons
// keep Grant.Valid fail-closed after any subsequent mutation without moving JSON
// or cryptographic algorithms into the pure authorization value package.
type policyGrantStartWitness struct {
	scope     string
	starts    int
	authority AcceptedPolicyAuthority
	recipe    artifact.Digest
}

func BindPolicyGrantStartWitness(g Grant, checkedScope []byte, starts int) (Grant, bool) {
	if g.Policy == nil || starts < 1 || starts > 16 || starts != g.Policy.MaxStartsPerExecution || !bytes.Equal(checkedScope, g.Scope) || len(checkedScope) < 2 || len(checkedScope) > GrantMaxScopeBytes {
		return Grant{}, false
	}
	a := g.Policy.Authority
	a.Owners = slices.Clone(a.Owners)
	a.Actions = slices.Clone(a.Actions)
	g.policyStartWitness = &policyGrantStartWitness{scope: string(checkedScope), starts: starts, authority: a, recipe: g.Policy.RecipeDigest}
	return g, true
}

func (g Grant) policyStartWitnessValid() bool {
	p := g.Policy
	if p == nil {
		return false
	}
	if p.MaxStartsPerExecution == 0 {
		return g.policyStartWitness == nil
	}
	w := g.policyStartWitness
	return w != nil && w.starts == p.MaxStartsPerExecution && w.scope == string(g.Scope) && w.recipe == p.RecipeDigest && samePolicyGrantAuthority(w.authority, p.Authority)
}

func samePolicyGrantAuthority(a, b AcceptedPolicyAuthority) bool {
	return a.InstallationID == b.InstallationID && a.PolicyUID == b.PolicyUID && a.Creator == b.Creator && a.Executor == b.Executor && a.ScopeDigest == b.ScopeDigest && a.ClusterID == b.ClusterID && a.NamespaceUID == b.NamespaceUID && a.WorkloadUID == b.WorkloadUID && a.Delegation == b.Delegation && a.Limits == b.Limits && a.IssuedAt.Equal(b.IssuedAt) && a.NotAfter.Equal(b.NotAfter) && slices.Equal(a.Owners, b.Owners) && slices.Equal(a.Actions, b.Actions)
}
