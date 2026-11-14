package kubernetes

import (
	"encoding/hex"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

func configurationLaunchValid(in contracts.ConfigurationRuntimeRoles, state contracts.ConfigurationRuntimeRoleState, ids map[string]bool, now time.Time) bool {
	l := state.Launch
	if l == nil || state.Projection == nil || state.Projection.SecretUID == "" || l.ProjectionUID != state.Projection.SecretUID || !authorization.UUID(l.OperationID) || ids[l.OperationID] || l.ClaimedAt.Before(state.CreatedAt) || l.ClaimedAt.After(now) || !l.ClaimedAt.Equal(l.ClaimedAt.Truncate(time.Microsecond)) || !l.Until.After(l.ClaimedAt) || l.Until.Sub(l.ClaimedAt) > 5*time.Second || l.Until.After(state.Until) || l.Until.After(l.Sources.FreshUntil) || !configurationRoleSourceMatches(in, l.Sources, l.ClaimedAt) || !configurationLaunchVersion(l.InertResourceVersion) {
		return false
	}
	d, err := hex.DecodeString(l.RunningDigest)
	if err != nil || len(d) != 32 || hex.EncodeToString(d) != l.RunningDigest || l.RunningDigest == strings.Repeat("0", 64) || l.RunningDigest == l.Sources.WorkloadDigest {
		return false
	}
	for _, ref := range []contracts.WorkerObjectReference{l.Configuration, l.Providers} {
		if !installationRefValid(ref.Name, ref.UID) || !authorization.UUID(ref.UID) {
			return false
		}
	}
	if l.Configuration.Name == in.FleetSource.Name || l.Configuration.Name == in.OwnerSource.Name || l.Configuration.UID == l.Providers.UID || l.Providers.UID == l.ProjectionUID {
		return false
	}
	for _, r := range state.Roles {
		if r.Claim == nil || r.Receipt == nil || !configurationRoleSameSources(r.Claim.Sources, l.Sources) {
			return false
		}
	}
	if r := l.Receipt; r != nil {
		if !configurationLaunchVersion(r.ResourceVersion) || r.ResourceVersion == l.InertResourceVersion || r.ObservedAt.Before(l.ClaimedAt) || r.ObservedAt.After(now) || !r.ObservedAt.Equal(r.ObservedAt.Truncate(time.Microsecond)) {
			return false
		}
	}
	return true
}

func configurationLaunchVersion(s string) bool {
	return len(s) > 0 && len(s) <= 128 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
