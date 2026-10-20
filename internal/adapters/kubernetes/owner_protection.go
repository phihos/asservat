package kubernetes

import (
	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

var _ app.OwnerProtectionReader = (*OwnerWorkloadProtection)(nil)

type ownerProtectionDiagnostic struct {
	step  string
	cause error
}

func (e *ownerProtectionDiagnostic) Error() string     { return cfg.ErrUnavailable.Error() }
func (e *ownerProtectionDiagnostic) Unwrap() error     { return e.cause }
func (e *ownerProtectionDiagnostic) FixedStep() string { return e.step }

// Preserve the boundary's original error class, including its normalization
// of final reads to ErrChanged. Only this adapter's concrete closed codes may
// describe the underlying read; arbitrary FixedStep and Error text are ignored.
func ownerProtectionError(phase string, class, detail error) error {
	step := "protection." + phase
	switch {
	case errors.Is(detail, context.DeadlineExceeded):
		step += "/deadline"
	case errors.Is(detail, context.Canceled):
		step += "/canceled"
	default:
		var native *configurationWorkerDiagnostic
		if errors.As(detail, &native) && native != nil {
			step += "/" + native.check.String()
		}
	}
	return &ownerProtectionDiagnostic{step: step, cause: class}
}

func (g *OwnerWorkloadProtection) ReadOwnerProtection(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
	var zero value.OwnerProtection
	if g == nil || g.observer == nil || ctx == nil || !p.Valid() || g.observer.clusterID != p.ClusterID || g.plan.ControlNamespace.Name != p.Namespace || g.plan.ControlNamespace.UID != p.NamespaceUID || g.plan.Deployment != p.Deployment || g.plan.DeploymentUID != p.DeploymentUID {
		return zero, ownerProtectionError("binding", value.ErrInvalid, nil)
	}
	start := g.observer.now()
	digest, until, err := g.Current(ctx)
	if err != nil {
		return zero, err
	}
	out := value.OwnerProtection{Pool: p, Digest: digest, ObservedAt: start, FreshUntil: identity.Earlier(start.Add(5*time.Second), until)}
	if !out.Valid(g.observer.now()) {
		return zero, ownerProtectionError("result", value.ErrUnavailable, nil)
	}
	if err = ctx.Err(); err != nil {
		return zero, ownerProtectionError("result-context", value.ErrUnavailable, err)
	}
	return out, nil
}
