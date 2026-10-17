package kubernetes

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	authn "k8s.io/api/authentication/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// RegionalCapacityNames are the region's ADR-197 capacity probe namespace and
// selector guard, derived from the connector namespace.
func RegionalCapacityNames(namespace string) (probe, guard string) {
	return namespace + "-capacity-probe", namespace + "-capacity-ns-guard"
}

// regionalCapacityRBAC is the connector account's cluster-wide metadata reads
// for capacity observation and its read of the selector guard; the probe
// account's token right is a Role in the probe namespace.
func regionalCapacityRBAC(namespace string) []rbac.PolicyRule {
	_, guard := RegionalCapacityNames(namespace)
	return []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces", "pods"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{guard}, Verbs: []string{"get"}},
	}
}

// ensureRegionalCapacity creates the empty probe namespace and account, the
// connector account's right to mint that account's tokens, and the selector
// guard over the offer's keys (ADR-197 decision 4).
func ensureRegionalCapacity(call context.Context, api kubernetes.Interface, p RegionalInstallPlan, admins []cfg.KubernetesActor, audience string) (contracts.RegionalCapacity, error) {
	o := p.Offer.Capacity
	keys := slices.Sorted(slices.Values(o.Keys))
	out := contracts.RegionalCapacity{OperationAddress: o.OperationAddress, Owner: o.Owner, Keys: keys, ProbeAudience: audience}
	probe, guard := RegionalCapacityNames(p.Namespace)
	var err error
	if out.ProbeNamespace, out.ProbeAccount, err = ensureCapacityProbe(call, api, probe, keys, p.Namespace, RegionalAccount); err != nil {
		return out, err
	}
	policy, binding, err := CapacityNamespaceAdmission(regionalCapacityPlan(out, guard, admins))
	if err != nil {
		return out, err
	}
	out.NamespaceGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins)
	return out, err
}

func regionalCapacityPlan(c contracts.RegionalCapacity, guard string, admins []cfg.KubernetesActor) cfg.CapacityNamespaceAdministration {
	return cfg.CapacityNamespaceAdministration{Name: guard, Administrators: admins, Keys: c.Keys,
		ProbeNamespace: cfg.NamespaceRef{Name: c.ProbeNamespace.Name, UID: c.ProbeNamespace.UID}, ProbeAccount: cfg.NamespaceRef{Name: c.ProbeAccount.Name, UID: c.ProbeAccount.UID}}
}

// proveRegionalCapacity proves the selector guard as the connector process
// will: the connector account reads it and the probe account's actual
// dry-run is denied. It returns the digest the join record asserts.
func proveRegionalCapacity(ctx context.Context, config *rest.Config, api kubernetes.Interface, p RegionalInstallPlan, c contracts.RegionalCapacity, admins []cfg.KubernetesActor) (artifact.Digest, error) {
	var zero artifact.Digest
	sub := func(step string, err error) error { return &regionalInstallError{step: step, cause: err} }
	client := func(namespace, account string, scope cfg.NamespaceRef) (*PermissionClient, func(), error) {
		token, err := api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, account, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
		if err != nil || token.Status.Token == "" {
			return nil, func() {}, cfg.ErrUnavailable
		}
		minted := rest.AnonymousClientConfig(config)
		minted.BearerToken = token.Status.Token
		out, err := NewPermissionClient(minted, p.Bootstrap.Binding.ClusterID, scope, time.Now)
		return out, func() { minted.BearerToken = "" }, err
	}
	scope := cfg.NamespaceRef{Name: c.ProbeNamespace.Name, UID: c.ProbeNamespace.UID}
	read, clear, err := client(p.Namespace, RegionalAccount, scope)
	defer clear()
	if err != nil {
		return zero, sub("capacity-clients", err)
	}
	probe, clearProbe, err := client(c.ProbeNamespace.Name, c.ProbeAccount.Name, scope)
	defer clearProbe()
	if err != nil {
		return zero, sub("capacity-clients", err)
	}
	_, name := RegionalCapacityNames(p.Namespace)
	g := c.NamespaceGuard
	guard, err := NewCapacityNamespaceGuard(read, probe, regionalCapacityPlan(c, name, admins), GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
	if err != nil {
		return zero, sub("capacity-guard", err)
	}
	// The new policy applies asynchronously; a failed proof has no effect.
	var last error
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		n, err := guard.CapacityNamespaceProtection(ctx)
		if err == nil {
			return n.Digest, nil
		}
		if last = sub("capacity-guard", err); ctx.Err() != nil {
			break
		}
	}
	return zero, regionalProofFailure(last)
}
