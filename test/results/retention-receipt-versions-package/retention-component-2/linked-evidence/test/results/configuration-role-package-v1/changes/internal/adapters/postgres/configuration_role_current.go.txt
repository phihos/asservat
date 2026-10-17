package postgres

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Compare immutable source values, never refresh the stored first observation.
// Exact lookup after a lost role-creation reply may use a later current proof;
// it cannot perform another CREATE or replace the original claim/provenance.
func sameConfigurationRoleSource(a, b contracts.ConfigurationRoleObservation) bool {
	a.ObservedAt, a.FreshUntil = time.Time{}, time.Time{}
	b.ObservedAt, b.FreshUntil = time.Time{}, time.Time{}
	a.Fleet.ObservedAt, a.Fleet.FreshUntil = time.Time{}, time.Time{}
	b.Fleet.ObservedAt, b.Fleet.FreshUntil = time.Time{}, time.Time{}
	a.Owner.ObservedAt, a.Owner.FreshUntil = time.Time{}, time.Time{}
	b.Owner.ObservedAt, b.Owner.FreshUntil = time.Time{}, time.Time{}
	return a == b
}
func configurationRoleCurrentShape(in contracts.ConfigurationRuntimeRoles, p contracts.ConfigurationRoleObservation, now time.Time) bool {
	if p.InstallationID != in.InstallationID || p.ClusterID != in.ClusterID || p.NamespaceUID != in.Namespace.UID || p.DeploymentUID != in.Deployment.UID || p.AccountUID != in.ServiceAccount.UID || !authorization.UUID(p.IssuerEpoch) || p.Fleet.UID != in.FleetSource.UID || p.Owner.UID != in.OwnerSource.UID || !identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) {
		return false
	}
	digest := func(s string) bool {
		b, e := hex.DecodeString(s)
		return e == nil && len(b) == 32 && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
	}
	if !digest(p.WorkloadDigest) || !digest(p.GuardDigest) {
		return false
	}
	for _, r := range []contracts.ConfigurationRoleSourceRevision{p.Fleet, p.Owner} {
		if r.Generation < 1 || r.Generation > 2147483647 || !digest(r.Digest) || !identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second) || p.FreshUntil.After(r.FreshUntil) {
			return false
		}
	}
	return true
}

// Called under recovery then installation-role locks. The proof was obtained
// from the concrete protected source/root and is bounded by the caller's
// original interval. It replaces only stale stored observation freshness for
// this purpose-fixed credential bootstrap, never incarnation/activation/epoch
// or suspension checks. No observation is written here.
func (s *ConfigurationRuntimeSQLRoles) currentSources(ctx context.Context, q publicRoleQuery, p contracts.ConfigurationRoleObservation) error {
	var now time.Time
	var valid bool
	e := q.QueryRow(ctx, `SELECT clock_timestamp(),EXISTS(
 SELECT 1 FROM public.fleet_initial_activation a JOIN public.fleet_current_trust t ON t.installation_id=a.installation_id
 WHERE a.installation_id=$1 AND a.claim_id=$2 AND a.audit_receipt_json IS NOT NULL AND a.activated_at IS NOT NULL
 AND NOT t.suspended AND NOT t.recovery_blocked AND t.issuer_epoch=$3 AND t.source_uid=$4
 AND t.source_generation<=$5
 AND (t.source_generation<$5 OR t.source_digest=decode($6,'hex'))
 AND NOT pg_is_in_recovery())`, s.input.InstallationID, s.input.InitialClaimID, p.IssuerEpoch, p.Fleet.UID, p.Fleet.Generation, p.Fleet.Digest).Scan(&now, &valid)
	if e != nil || !valid || ctx.Err() != nil || !configurationRoleCurrentShape(s.input, p, now) {
		return cfg.ErrUnavailable
	}
	return nil
}
