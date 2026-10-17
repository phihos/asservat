package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InitialPreparationHistoryProtection uses current bootstrap identities solely
// for exact historical metadata. It cannot create inputs, issue credentials,
// consume a witness, reactivate SQL, or complete an uncertain launch.
type InitialPreparationHistoryProtection struct {
	preparer *InitialPreparer
	scope    fleet.InstallationWitnessScope
	plan     artifact.Digest
}

var _ app.InitialInstallationReadAuthority = (*InitialPreparationHistoryProtection)(nil)

// NewHistoryProtection requires original acknowledged inputs and the explicit
// new-installation capability. Its subsequent checks re-read the root and exact
// immutable inputs; retained constructor facts never become current authority.
func (s *InitialPreparer) NewHistoryProtection(ctx context.Context) (*InitialPreparationHistoryProtection, error) {
	if !s.HandoverEnabled() || ctx == nil {
		return nil, cfg.ErrInvalid
	}
	_, w, c, _, e := s.passiveHandover(ctx)
	if e != nil {
		return nil, e
	}
	if w.Activation == nil || w.Activation.Handover == nil {
		return nil, cfg.ErrChanged
	}
	scope := initialPreparationWitnessScope(c)
	if !scope.Valid() {
		return nil, cfg.ErrChanged
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, cfg.ErrInvalid
	}
	return &InitialPreparationHistoryProtection{s, scope, artifact.Digest(sha256.Sum256(raw))}, nil
}
func (p *InitialPreparationHistoryProtection) Scope() (fleet.InstallationWitnessScope, artifact.Digest) {
	if p == nil {
		return fleet.InstallationWitnessScope{}, artifact.Digest{}
	}
	return p.scope, p.plan
}
func (p *InitialPreparationHistoryProtection) CheckInitialInstallationRead(ctx context.Context, scope fleet.InstallationWitnessScope, plan artifact.Digest) (time.Time, error) {
	if p == nil || p.preparer == nil || ctx == nil || scope != p.scope || plan != p.plan {
		return time.Time{}, cfg.ErrInvalid
	}
	_, w, c, until, e := p.preparer.passiveHandover(ctx)
	if e != nil {
		return time.Time{}, e
	}
	raw, e := json.Marshal(c)
	if e != nil || w.Activation == nil || w.Activation.Handover == nil || initialPreparationWitnessScope(c) != scope || artifact.Digest(sha256.Sum256(raw)) != plan {
		return time.Time{}, cfg.ErrChanged
	}
	return until, nil
}
func initialPreparationWitnessScope(c contracts.InitialInstaller) fleet.InstallationWitnessScope {
	return fleet.InstallationWitnessScope{InstallationID: c.InstallationID, IssuerEpoch: c.IssuerEpoch, ClusterID: c.ClusterID, Namespace: c.Namespace.Name, NamespaceUID: c.Namespace.UID, Name: c.Witness.Name, UID: c.Witness.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID}
}

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
