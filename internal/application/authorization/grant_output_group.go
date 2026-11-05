package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

// GrantedOutputResolver resolves only an existing published member of this
// exact accepted capture group. It grants no permission or recovery authority.
type GrantedOutputResolver interface {
	ResolveGrantedOutput(context.Context, string, artifact.DownloadScope, string) (value.VerifiedOutput, *value.GrantOutputGroup, error)
}

func (s GrantService) outputGroup(ctx context.Context, g value.Grant, o value.VerifiedOutput) (*value.GrantOutputGroup, error) {
	if g.Kind != value.GrantAdHocCapture || o.CaptureID == g.CaptureID && o.ExecutionDigest == g.ExecutionDigest {
		return nil, nil
	}
	reader, ok := s.Store.(GrantedOutputResolver)
	if !ok {
		return nil, value.ErrGrantScope
	}
	out, group, err := reader.ResolveGrantedOutput(ctx, g.ID, rawDownloadScope(s.RootID, g.Requester, o), o.ActionID)
	if err != nil || out != o || group == nil || !group.Matches(g, o) {
		return nil, value.ErrGrantScope
	}
	return group, nil
}
func (s GrantService) grantedScopeOutput(ctx context.Context, g value.Grant, scope artifact.DownloadScope, action string) (value.VerifiedOutput, *value.GrantOutputGroup, bool) {
	if out, ok := rawOutputForScope(g, scope, action); ok {
		return out, nil, true
	}
	reader, ok := s.Store.(GrantedOutputResolver)
	if !ok || g.Kind != value.GrantAdHocCapture {
		return value.VerifiedOutput{}, nil, false
	}
	out, group, err := reader.ResolveGrantedOutput(ctx, g.ID, scope, action)
	if err != nil || group == nil || !group.Matches(g, out) {
		return value.VerifiedOutput{}, nil, false
	}
	return out, group, true
}
