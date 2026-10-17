package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func validProviderTime(v time.Time) bool { return !v.IsZero() && v.Location() == time.UTC }
func (s *InitialPreparer) validPrivateProviders(v contracts.InitialPreparationPrivateState) bool {
	p := v.Providers
	if p == nil {
		return true
	}
	if s.providers == nil || v.SQL == nil || v.SQL.Secret == nil || p.ProfileDigest != preparationDigest(*s.providers) || !identity.Text(p.Parent.Accessor, 128) || !validProviderTime(p.Parent.IssuedAt) || !validProviderTime(p.Parent.ExpiresAt) || !p.Parent.IssuedAt.Before(p.Parent.ExpiresAt) || p.Parent.ExpiresAt.Sub(p.Parent.IssuedAt) > 901*time.Second {
		return false
	}
	seen := map[string]bool{v.SQL.OperationID: true, v.Probe.AnchorOperationID: true, v.Probe.Issue.ID: true}
	for n, i := range []*contracts.InitialProviderIssue{p.Wrap, p.Unwrap} {
		if i == nil {
			if n == 0 && (p.Unwrap != nil || p.Projection != nil) {
				return false
			}
			continue
		}
		if n == 1 && (p.Wrap == nil || p.Wrap.Response == nil) {
			return false
		}
		if !authorization.UUID(i.ID) || seen[i.ID] || !validInitialPrivateTime(i.StartedAt) || !validInitialPrivateTime(i.Until) || !i.StartedAt.Before(i.Until) || i.Until.Sub(i.StartedAt) > 5*time.Second || !i.Until.Before(i.ExpiresBefore) || !i.ExpiresBefore.Equal(p.Parent.ExpiresAt) {
			return false
		}
		seen[i.ID] = true
		if r := i.Response; r != nil {
			if !initialProviderASCII(r.Token, contracts.InitialProviderTokenMaxBytes) || !identity.Text(r.Accessor, 128) || r.Accessor == p.Parent.Accessor || !validProviderTime(r.IssuedAt) || !validProviderTime(r.ExpiresAt) || r.IssuedAt.Before(i.StartedAt) || r.IssuedAt.After(i.Until) || !r.IssuedAt.Before(r.ExpiresAt) || r.ExpiresAt.After(i.ExpiresBefore) {
				return false
			}
			if n == 1 && (r.Token == p.Wrap.Response.Token || r.Accessor == p.Wrap.Response.Accessor) {
				return false
			}
		}
	}
	if p.Projection != nil {
		if p.Projection.CreateClosed && (!s.HandoverEnabled() || p.Projection.Secret == nil) {
			return false
		}
		if p.Unwrap == nil || p.Unwrap.Response == nil || !authorization.UUID(p.Projection.OperationID) || seen[p.Projection.OperationID] {
			return false
		}
		if r := p.Projection.Secret; r != nil && (r.Name != s.plan.Workload.Credentials || !authorization.UUID(r.UID)) {
			return false
		}
	}
	return true
}
func (s *InitialPreparer) privateProviderTransition(old, next contracts.InitialPreparationPrivateState) bool {
	if old.SQL == nil || old.SQL.Secret == nil || next.Providers == nil {
		return false
	}
	copy := old
	if old.Providers == nil {
		copy.Providers = next.Providers
		return next.Providers.Wrap == nil && next.Providers.Unwrap == nil && next.Providers.Projection == nil && equalJSON(copy, next)
	}
	p := *old.Providers
	copy.Providers = &p
	for n, i := range []*contracts.InitialProviderIssue{p.Wrap, p.Unwrap} {
		replacement := next.Providers.Wrap
		if n == 1 {
			replacement = next.Providers.Unwrap
		}
		if i == nil {
			if n == 0 {
				p.Wrap = replacement
			} else {
				p.Unwrap = replacement
			}
			return replacement != nil && replacement.Response == nil && equalJSON(copy, next)
		}
		if i.Response == nil {
			if replacement == nil {
				return false
			}
			issue := *i
			issue.Response = replacement.Response
			if n == 0 {
				p.Wrap = &issue
			} else {
				p.Unwrap = &issue
			}
			return issue.Response != nil && equalJSON(copy, next)
		}
	}
	if p.Projection == nil {
		p.Projection = next.Providers.Projection
		return p.Projection != nil && p.Projection.Secret == nil && equalJSON(copy, next)
	}
	if p.Projection.Secret == nil && next.Providers.Projection != nil {
		projection := *p.Projection
		projection.Secret = next.Providers.Projection.Secret
		projection.CreateClosed = next.Providers.Projection.CreateClosed
		p.Projection = &projection
		return projection.Secret != nil && equalJSON(copy, next)
	}
	return false
}
