package capacity

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// ComposeEnrollmentObservation joins independently current protected facts.
// The plan is compiled here from the exact selection and protected account-key
// version; a caller cannot substitute a bare digest or an allocation identity.
// SQL verifies the complete plan and every accepted source fence again.
// A new global source heartbeat alone cannot refresh namespace/workload facts.
func ComposeEnrollmentObservation(source AcceptedCapacitySource, guard CapacityNamespaceProtection, workload CapacityWorkloadObservation, permissions AcceptedCapacityPermissions, recovery artifact.RecoveryProof, accountVersion string, now time.Time) (EnrollmentObservation, SelectedBudget, error) {
	var zero EnrollmentObservation
	var noBudget SelectedBudget
	if !source.Valid(now) || !guard.Valid(now) || !workload.Valid(now) || !permissions.Valid(now) || !recovery.Valid(now) || !identity.Text(accountVersion, 64) || source.InstallationID != recovery.InstallationID || source.RootID != permissions.RootID || guard.ClusterID != workload.Namespace.ClusterID {
		return zero, noBudget, capacityStage("inputs", cfg.ErrUnavailable)
	}
	k := WorkloadCapacityKey{source.RootID, workload.Namespace.ClusterID, workload.Namespace.Namespace.UID, workload.Workload.UID}
	covered := false
	for _, scope := range permissions.Scopes {
		if scope.Covers(k, now) {
			covered = true
			break
		}
	}
	if !covered {
		return zero, noBudget, capacityStage("permission-scope", ErrCapacityNotAllocated)
	}
	selected, e := SelectBudget(source.Observation.Snapshot, workload.Namespace, guard.Keys, now)
	if e != nil {
		return zero, noBudget, capacityStage("select", e)
	}
	digest, e := SelectedCapacitySourceDigest(source.Observation.Snapshot, selected.Pool.Name)
	if e != nil {
		return zero, noBudget, capacityStage("source-digest", e)
	}
	plan, e := CompileEnrollmentPlan(source, selected, accountVersion, now)
	if e != nil {
		return zero, noBudget, capacityStage("plan", e)
	}
	labels := make(map[string]string, len(guard.Keys))
	for _, k := range guard.Keys {
		if value, ok := workload.Namespace.Labels[k]; ok {
			labels[k] = value
		}
	}
	start, end := source.ObservedAt, source.FreshUntil
	for _, interval := range [][2]time.Time{{guard.ObservedAt, guard.FreshUntil}, {workload.ObservedAt, workload.FreshUntil}, {workload.Namespace.ObservedAt, workload.Namespace.FreshUntil}, {permissions.ObservedAt, permissions.FreshUntil}, {recovery.ObservedAt, recovery.FreshUntil}, {selected.ObservedAt, selected.FreshUntil}} {
		if interval[0].After(start) {
			start = interval[0]
		}
		end = identity.Earlier(end, interval[1])
	}
	// SQL precision only narrows the common interval. Never round a deadline up
	// or represent a proof as observed before its actual original observation.
	if start.Nanosecond()%1000 != 0 {
		start = start.Truncate(time.Microsecond).Add(time.Microsecond)
	}
	end = end.Truncate(time.Microsecond)
	out := EnrollmentObservation{Key: k, SourceRevision: source.Revision, SourceDigest: digest, PlanDigest: plan.Digest(), Plan: plan, NamespaceLabels: labels, NamespaceGuardDigest: guard.Digest, NamespaceResourceVersion: workload.Namespace.ResourceVersion, WorkloadResourceVersion: workload.WorkloadResourceVersion, PermissionEpoch: permissions.Epoch, PermissionSequence: permissions.Sequence, PermissionTrust: permissions.TrustDigest, Recovery: recovery, ObservedAt: start, FreshUntil: end}
	if !out.Valid(now) {
		return zero, noBudget, cfg.ErrUnavailable
	}
	return out, selected, nil
}
