package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkHistoryProbe proves the current, explicitly retained bootstrap account.
// Neither a rotated bearer token nor cached API authentication may replace its
// pinned account UID, namespace UID, or make it an installation administrator.
func (s *InitialPreparer) checkHistoryProbe(ctx context.Context) error {
	if !s.HandoverEnabled() || s.plan.HistoryProbe == nil {
		return cfg.ErrInvalid
	}
	ref := *s.plan.HistoryProbe
	raw, e := s.protection.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if e != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.plan.BootstrapNamespace.Name+":"+ref.Name || who.Status.UserInfo.UID != ref.UID {
		return cfg.ErrUnavailable
	}
	for _, a := range preparerAdministration(s.plan).Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return cfg.ErrDenied
		}
	}
	raw, e = s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.BootstrapNamespace.Name+"/serviceaccounts/"+ref.Name, nil)
	var account core.ServiceAccount
	if e != nil || strictGuardJSON(raw, &account) != nil || account.APIVersion != "v1" || account.Kind != "ServiceAccount" || !ownerMetadata(account.ObjectMeta, s.plan.BootstrapNamespace.Name, ref.Name, ref.UID) {
		return cfg.ErrChanged
	}
	ns, e := s.protection.observer.namespace(ctx, cfg.NamespaceRef{Name: s.plan.BootstrapNamespace.Name, UID: s.plan.BootstrapNamespace.UID})
	if e != nil || ns.Deleting {
		return cfg.ErrChanged
	}
	return nil
}

// finalHandoverProtection reuses the exact original workload admission policy,
// but its independent denied configuration probe is a current bootstrap account.
// It does not use the expired target probe token or grant that account access to
// the witness, persistent configuration updates, or activation effects.
func (s *InitialPreparer) finalHandoverProtection(c contracts.InitialInstaller) (*configMapProtection, error) {
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observer, probe := *s.protection.observer, *s.protection.probe
	observer.control, probe.control = ns, ns
	wp := cfg.InitialWorkloadAdministration{Handover: c.Handover == contracts.InitialPreparationHandoverProtocol, Name: c.WorkloadGuard.Name, Configuration: c.Configuration, Witness: c.Witness.Name, FleetSource: c.FleetSource.Name, ControlNamespace: ns, PodName: c.Pod.Name, PodUID: c.Pod.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: c.ProbeAccount.Name, ProbeAccountUID: c.ProbeAccount.UID}
	for _, a := range c.WorkloadGuard.Administrators {
		wp.Administrators = append(wp.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	// Only the original acknowledged Pod's digest is accepted. The domain value
	// participates in native checks, never in a current credential deadline.
	digest, e := initialPreparationDigest(c.PodSpecDigest)
	if e != nil {
		return nil, e
	}
	wp.PodSpecDigest = digest
	pin := GuardPin{PolicyUID: c.WorkloadGuard.PolicyUID, PolicyGeneration: c.WorkloadGuard.PolicyGeneration, BindingUID: c.WorkloadGuard.BindingUID, BindingResourceVersion: c.WorkloadGuard.BindingResourceVersion}
	g, e := NewInitialWorkloadProtection(&observer, &probe, wp, pin)
	if e != nil {
		return nil, e
	}
	return g.guard, nil
}

// A public historical observation preserves the earliest original current
// administrator/continuity/final-guard interval through every blocking read.
func initialHandoverDeadline(ctx context.Context, now func() time.Time, until time.Time) error {
	if until.IsZero() || ctx.Err() != nil || !now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}
