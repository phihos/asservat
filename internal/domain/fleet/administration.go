package fleet

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Administration is a current administrator-protected installation projection.
// It assigns fleet management only, never workload/evidence or approval rights.
type Administration struct {
	InstallationID, IssuerEpoch, Issuer                   string
	Revision                                              identity.Revision
	Suspended                                             bool
	ObservedAt, FreshUntil                                time.Time
	Clients, Groups, DeliveryProfiles                     []string
	Subjects                                              []identity.Subject
	MaxActiveBootstraps, MaxBootstrapHistory, MaxClusters int
}

func (a Administration) Valid(now time.Time) bool {
	if !authorization.UUID(a.InstallationID) || !authorization.UUID(a.IssuerEpoch) || !identity.Text(a.Issuer, 2048) || !a.Revision.Valid() || !identity.Fresh(a.ObservedAt, a.FreshUntil, now, 5*time.Second) || len(a.Clients) == 0 || !identity.Strings(a.Clients, 64, 256) || !identity.Strings(a.Groups, 256, 256) || !identity.Strings(a.DeliveryProfiles, 16, 64) || len(a.Subjects) > 256 || a.MaxActiveBootstraps < 1 || a.MaxActiveBootstraps > 128 || a.MaxBootstrapHistory < a.MaxActiveBootstraps || a.MaxBootstrapHistory > 65536 || a.MaxClusters < 1 || a.MaxClusters > 1024 {
		return false
	}
	seen := map[identity.Subject]bool{}
	for _, s := range a.Subjects {
		if !identity.Text(s.ID, 256) || !identity.ValidKind(s.Kind) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// Operator reports whether the identity is one of the installation's fleet
// operators: a configured subject or group of the configured issuer, signed in
// with a configured client, while the administration is not suspended. Callers
// check Valid for both values first. ADR-237 reuses it as the installation-wide
// administrator check of the permission impact preview.
func (a Administration) Operator(i identity.Identity) bool {
	if a.Suspended || i.Principal.Issuer != a.Issuer || !slices.Contains(a.Clients, i.Principal.ClientID) {
		return false
	}
	permitted := slices.Contains(a.Subjects, identity.Subject{ID: i.Principal.Subject, Kind: i.Principal.Kind})
	for _, g := range i.Groups {
		permitted = permitted || slices.Contains(a.Groups, g)
	}
	return permitted
}

type EnrollmentAuthority struct {
	InstallationID, IssuerEpoch, DeliveryProfile          string
	Actor                                                 identity.Principal
	IdentityRevision, AdministrationRevision              identity.Revision
	CheckedAt, ValidUntil                                 time.Time
	MaxActiveBootstraps, MaxBootstrapHistory, MaxClusters int
}

func (a EnrollmentAuthority) Valid(now time.Time) bool {
	return authorization.UUID(a.InstallationID) && authorization.UUID(a.IssuerEpoch) && identity.Text(a.DeliveryProfile, 64) && a.Actor.Valid() && a.IdentityRevision.Valid() && a.AdministrationRevision.Valid() && identity.Fresh(a.CheckedAt, a.ValidUntil, now, 5*time.Second) && a.MaxActiveBootstraps >= 1 && a.MaxActiveBootstraps <= 128 && a.MaxBootstrapHistory >= a.MaxActiveBootstraps && a.MaxBootstrapHistory <= 65536 && a.MaxClusters >= 1 && a.MaxClusters <= 1024
}

func AuthorizeEnrollment(i identity.Identity, a Administration, profile string, now time.Time) (EnrollmentAuthority, error) {
	var out EnrollmentAuthority
	if !a.Valid(now) || !i.Valid(now) {
		return out, ErrUnavailable
	}
	if !a.Operator(i) || !slices.Contains(a.DeliveryProfiles, profile) {
		return out, ErrDenied
	}
	out = EnrollmentAuthority{InstallationID: a.InstallationID, IssuerEpoch: a.IssuerEpoch, DeliveryProfile: profile, Actor: i.Principal, IdentityRevision: i.Policy, AdministrationRevision: a.Revision, CheckedAt: now, ValidUntil: identity.Earlier(i.ValidUntil, a.FreshUntil), MaxActiveBootstraps: a.MaxActiveBootstraps, MaxBootstrapHistory: a.MaxBootstrapHistory, MaxClusters: a.MaxClusters}
	return out, nil
}
