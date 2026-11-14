package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	port "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

// RetentionGuard is the hub control namespace's current retention source
// observation. Kubernetes RBAC decides who may write retention policies; the
// runtime no longer re-verifies an admission policy or proves a dry-run
// denial (helm-native-install plan, slice 0). The digest is unchanged.
type RetentionGuard struct {
	observer *PermissionClient
	plan     value.RetentionAdministration
	digest   artifact.Digest
}

var _ port.PolicyProtectionReader = (*RetentionGuard)(nil)

func NewRetentionGuard(observer *PermissionClient, plan value.RetentionAdministration, pin GuardPin) (*RetentionGuard, error) {
	if observer == nil || observer.control != plan.ControlNamespace {
		return nil, value.ErrInvalid
	}
	own, digest, err := retentionGuardDigest(observer.clusterID, plan, pin)
	if err != nil {
		return nil, err
	}
	return &RetentionGuard{observer: observer, plan: own, digest: digest}, nil
}

func retentionGuardDigest(cluster string, plan value.RetentionAdministration, pin GuardPin) (value.RetentionAdministration, artifact.Digest, error) {
	var own value.RetentionAdministration
	encoded, err := json.Marshal(plan)
	if err != nil || json.Unmarshal(encoded, &own) != nil {
		return own, artifact.Digest{}, value.ErrInvalid
	}
	bound, err := json.Marshal(struct {
		Cluster string
		Plan    value.RetentionAdministration
		Pin     GuardPin
	}{cluster, own, pin})
	if err != nil {
		return own, artifact.Digest{}, value.ErrInvalid
	}
	return own, sha256.Sum256(bound), nil
}

// Digest is the guard's protection digest: the cluster, the plan and the pin.
// A retention source reference carries it (ADR-195).
func (g *RetentionGuard) Digest() artifact.Digest { return g.digest }

func (g *RetentionGuard) RetentionProtection(ctx context.Context) (port.SourceProtection, error) {
	var out port.SourceProtection
	if g == nil || g.observer == nil {
		return out, value.ErrUnavailable
	}
	start, err := controlNamespaceCurrent(ctx, g.observer, g.plan.ControlNamespace, 5*time.Second)
	if err != nil {
		return out, retentionGuardFailure("namespace", err)
	}
	return port.SourceProtection{SourceClusterID: g.observer.clusterID, ControlNamespaceUID: g.plan.ControlNamespace.UID, Digest: g.digest, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, nil
}

// retentionGuardFailure names the failed retention source check with fixed
// text only; errors.Is keeps the original class.
type retentionGuardError struct {
	check string
	cause error
}

func retentionGuardFailure(check string, cause error) error {
	return &retentionGuardError{check, cause}
}
func (e *retentionGuardError) Error() string     { return "retention guard " + e.check }
func (e *retentionGuardError) Unwrap() error     { return e.cause }
func (e *retentionGuardError) FixedStep() string { return "guard." + e.check }
