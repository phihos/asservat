package bootstrap

import (
	"context"
	"errors"
	"strings"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type ownerStartupPhase uint8

const (
	startupUnspecified ownerStartupPhase = iota
	startupFiles
	startupInputs
	startupDeploymentMode
	startupProcessPreconditions
	startupObserverClient
	startupProbeClient
	startupStartInputs
	startupCapacityInputs
	startupWorkloadGuard
	startupMountedIdentity
	startupIdentityReader
	startupNativeIdentity
	startupSqlCredential
	startupSqlRoleName
	startupSqlPool
	startupSqlRoleProof
	startupConfigurationReader
	startupAcceptedConfiguration
	startupOriginalPool
	startupIssuerRoots
	startupEnrollmentLedger
	startupEnrollmentAttester
	startupEndpoints
	startupProviderEffects
	startupProviderAudit
	startupAuditHttp
	startupAuditSealer
	startupAuditOpener
	startupAuditStoreHttp
	startupAuditStore
	startupCertificateIssuer
	startupPeerVerifier
	startupObservationInputs
	startupObservationWorkload
	startupObservationRuntime
	startupConstructorDeadline
	startupObservationListener
	startupFullDeployment
	startupFullListener
	startupNativeListener
	startupFullRuntime
	startupProviderPrime
	startupProviderSupervisor
	startupRuntimeSupervisor
	startupProviderClose
	startupRunPreconditions
	startupRuntimeInputs
	startupRuntimeConfiguration
	startupRuntimeRoots
	startupRuntimeEpoch
	startupServerCredentials
	startupClientCredentials
	startupObservationIngress
	startupServerName
	startupObservationHandler
	startupBootstrapServing
	startupPeerRoots
	startupRuntimeDeadline
	startupInitialIdentity
	startupRuntimeServing
	// startupProviderProof runs the provider proof once before priming, so a
	// native identity failure is reported apart from provider login.
	startupProviderProof
	// startupPublicProjection compares the immutable public runtime
	// projection with the mounted public root (ADR-194).
	startupPublicProjection
	// The promoted composition's regions after the identity layer.
	startupPublicPools
	startupWorkerRouting
	startupNativeConfiguration
	startupPublicIdentity
	startupPublicContext
	startupOwnerRuntime
	startupPublicDownloads
	startupPublicHandler
	startupNativeRuntime
	// startupClusterCatalog reads the guarded cluster catalog before the
	// native configuration (ADR-196 decision 7).
	startupClusterCatalog
	// startupOperationInputs records the regional capacity qualification and
	// composes the v2 operation server's inputs (ADR-197).
	startupOperationInputs
	// Owner runtime children, each a fixed server phase (ADR-197
	// diagnostics), and the v2 operation server's composition.
	startupOperationServing
	startupRunIdentity
	startupRunRelay
	startupRunRouter
	startupRunObservation
	startupRunNative
	startupRunOperation
	startupRunReadiness
	// The optional ADR-204 worker serving on the owner port.
	startupRunWorkerRouter
	startupRunWorkerEnrollment
	startupRunWorkerNative
)

func (v ownerStartupPhase) String() string {
	switch v {
	case startupUnspecified:
		return "unspecified"
	case startupFiles:
		return "files"
	case startupInputs:
		return "inputs"
	case startupDeploymentMode:
		return "deployment-mode"
	case startupProcessPreconditions:
		return "process-preconditions"
	case startupObserverClient:
		return "observer-client"
	case startupProbeClient:
		return "probe-client"
	case startupStartInputs:
		return "start-inputs"
	case startupCapacityInputs:
		return "capacity-inputs"
	case startupWorkloadGuard:
		return "workload-guard"
	case startupMountedIdentity:
		return "mounted-identity"
	case startupIdentityReader:
		return "identity-reader"
	case startupNativeIdentity:
		return "native-identity"
	case startupSqlCredential:
		return "sql-credential"
	case startupSqlRoleName:
		return "sql-role-name"
	case startupSqlPool:
		return "sql-pool"
	case startupSqlRoleProof:
		return "sql-role-proof"
	case startupConfigurationReader:
		return "configuration-reader"
	case startupAcceptedConfiguration:
		return "accepted-configuration"
	case startupOriginalPool:
		return "original-pool"
	case startupIssuerRoots:
		return "issuer-roots"
	case startupEnrollmentLedger:
		return "enrollment-ledger"
	case startupEnrollmentAttester:
		return "enrollment-attester"
	case startupEndpoints:
		return "endpoints"
	case startupProviderEffects:
		return "provider-effects"
	case startupProviderAudit:
		return "provider-audit"
	case startupAuditHttp:
		return "audit-http"
	case startupAuditSealer:
		return "audit-sealer"
	case startupAuditOpener:
		return "audit-opener"
	case startupAuditStoreHttp:
		return "audit-store-http"
	case startupAuditStore:
		return "audit-store"
	case startupCertificateIssuer:
		return "certificate-issuer"
	case startupPeerVerifier:
		return "peer-verifier"
	case startupObservationInputs:
		return "observation-inputs"
	case startupObservationWorkload:
		return "observation-workload"
	case startupObservationRuntime:
		return "observation-runtime"
	case startupConstructorDeadline:
		return "constructor-deadline"
	case startupObservationListener:
		return "observation-listener"
	case startupFullDeployment:
		return "full-deployment"
	case startupFullListener:
		return "full-listener"
	case startupNativeListener:
		return "native-listener"
	case startupFullRuntime:
		return "full-runtime"
	case startupProviderPrime:
		return "provider-prime"
	case startupProviderProof:
		return "provider-proof"
	case startupProviderSupervisor:
		return "provider-supervisor"
	case startupRuntimeSupervisor:
		return "runtime-supervisor"
	case startupProviderClose:
		return "provider-close"
	case startupRunPreconditions:
		return "run-preconditions"
	case startupRuntimeInputs:
		return "runtime-inputs"
	case startupRuntimeConfiguration:
		return "runtime-configuration"
	case startupRuntimeRoots:
		return "runtime-roots"
	case startupRuntimeEpoch:
		return "runtime-epoch"
	case startupServerCredentials:
		return "server-credentials"
	case startupClientCredentials:
		return "client-credentials"
	case startupObservationIngress:
		return "observation-ingress"
	case startupServerName:
		return "server-name"
	case startupObservationHandler:
		return "observation-handler"
	case startupBootstrapServing:
		return "bootstrap-serving"
	case startupPeerRoots:
		return "peer-roots"
	case startupRuntimeDeadline:
		return "runtime-deadline"
	case startupInitialIdentity:
		return "initial-identity"
	case startupRuntimeServing:
		return "runtime-serving"
	case startupPublicPools:
		return "public-pools"
	case startupWorkerRouting:
		return "worker-routing"
	case startupNativeConfiguration:
		return "native-configuration"
	case startupPublicIdentity:
		return "public-identity"
	case startupPublicContext:
		return "public-context"
	case startupClusterCatalog:
		return "cluster-catalog"
	case startupOperationInputs:
		return "operation-inputs"
	case startupOperationServing:
		return "operation-serving"
	case startupRunIdentity:
		return "run-identity"
	case startupRunRelay:
		return "run-relay"
	case startupRunRouter:
		return "run-router"
	case startupRunObservation:
		return "run-observation"
	case startupRunNative:
		return "run-native"
	case startupRunOperation:
		return "run-operation"
	case startupRunReadiness:
		return "run-readiness"
	case startupRunWorkerRouter:
		return "run-worker-router"
	case startupRunWorkerEnrollment:
		return "run-worker-enrollment"
	case startupRunWorkerNative:
		return "run-worker-native"
	case startupOwnerRuntime:
		return "owner-runtime"
	case startupPublicDownloads:
		return "public-downloads"
	case startupNativeRuntime:
		return "native-runtime"
	case startupPublicHandler:
		return "public-handler"
	case startupPublicProjection:
		return "public-projection"
	default:
		return "unspecified"
	}
}

// This is an internal error chain, not a provider-error rendering surface.
// Underlying causes remain available to errors.Is/As; all text is closed.
type ownerStartupFailure struct {
	phase ownerStartupPhase
	role  string
	cause error
}

func (e *ownerStartupFailure) Error() string { return OwnerStartupDiagnostic(e) }
func (e *ownerStartupFailure) Unwrap() error { return e.cause }
func ownerStartupError(phase ownerStartupPhase, role string, cause error) error {
	if cause == nil {
		cause = mounts.ErrUnavailable
	}
	return &ownerStartupFailure{phase: phase, role: ownerStartupRole(role), cause: cause}
}
func ownerStartupAnnotate(phase *ownerStartupPhase, role *string, result *error) {
	if *result != nil {
		*result = ownerStartupError(*phase, *role, *result)
	}
}
func ownerStartupRole(s string) string {
	switch s {
	case "enrollment", "audit", "activation", "registry", "owner-runtime", "server", "client":
		return s
	default:
		return "none"
	}
}
func ownerStartupReason(e error) string {
	switch {
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, context.Canceled):
		return "cancelled"
	case apierrors.IsForbidden(e):
		return "forbidden"
	case apierrors.IsUnauthorized(e):
		return "unauthorized"
	case apierrors.IsNotFound(e):
		return "not-found"
	case errors.Is(e, contracts.ErrPublicRuntimeLayout):
		return "unsupported-development-layout"
	case errors.Is(e, cfg.ErrChanged):
		return "changed"
	case errors.Is(e, cfg.ErrDenied), errors.Is(e, value.ErrDenied):
		return "denied"
	case errors.Is(e, cfg.ErrInvalid), errors.Is(e, value.ErrInvalid):
		return "invalid"
	case errors.Is(e, mounts.ErrUnavailable), errors.Is(e, cfg.ErrUnavailable), errors.Is(e, value.ErrUnavailable):
		return "unavailable"
	default:
		return "other"
	}
}

// OwnerStartupDiagnostic contains only fixed phase/purpose/check/reason words.
// It never formats an underlying error, identifier, path, endpoint or credential.
func OwnerStartupDiagnostic(err error) string {
	phase, role := startupUnspecified, "none"
	var f *ownerStartupFailure
	if errors.As(err, &f) {
		phase, role = f.phase, ownerStartupRole(f.role)
		for {
			var next *ownerStartupFailure
			if !errors.As(f.cause, &next) {
				break
			}
			f = next
			phase, role = f.phase, ownerStartupRole(f.role)
		}
	}
	native, detail := "unspecified", "unspecified"
	var n *kube.OwnerIdentityReadFailure
	if errors.As(err, &n) {
		native, detail = n.Check().String(), n.Detail().String()
	}
	sql, sqlReason := "unknown", "unspecified"
	var p *postgres.OwnerConfigurationReadFailure
	if errors.As(err, &p) {
		sql, sqlReason = p.Check().String(), p.Reason().String()
	}
	return "owner startup failed: phase=" + phase.String() + " role=" + role + " reason=" + ownerStartupReason(err) + " native=" + native + " detail=" + detail + " sql=" + sql + " sql-reason=" + sqlReason
}

// OwnerStartupDiagnosticLine accepts exactly the bounded closed log record.
// Native test collection uses this to discard all unrelated/raw process output.
// Recognition is diagnostic only: a log line cannot establish runtime identity.
func OwnerStartupDiagnosticLine(line string) (string, bool) {
	if len(line) > 512 {
		return "", false
	}
	fields := strings.Split(line, " ")
	if len(fields) != 10 || fields[0] != "owner" || fields[1] != "startup" || fields[2] != "failed:" {
		return "", false
	}
	keys := []string{"phase=", "role=", "reason=", "native=", "detail=", "sql=", "sql-reason="}
	for i, key := range keys {
		if !strings.HasPrefix(fields[i+3], key) {
			return "", false
		}
		v := strings.TrimPrefix(fields[i+3], key)
		valid := false
		switch i {
		case 0:
			for n := 0; n < 256; n++ {
				if ownerStartupPhase(n).String() == v {
					valid = true
					break
				}
			}
		case 1:
			valid = ownerStartupRole(v) == v
		case 2:
			switch v {
			case "deadline", "cancelled", "forbidden", "unauthorized", "not-found", "changed", "denied", "invalid", "unavailable", "other", "unsupported-development-layout":
				valid = true
			}
		case 3, 4:
			for n := 0; n < 256; n++ {
				if kube.OwnerIdentityReadCheck(n).String() == v {
					valid = true
					break
				}
			}
		case 5:
			for n := 0; n < 256; n++ {
				if postgres.OwnerConfigurationReadCheck(n).String() == v {
					valid = true
					break
				}
			}
		case 6:
			for n := 0; n < 256; n++ {
				if postgres.OwnerConfigurationReadReason(n).String() == v {
					valid = true
					break
				}
			}
		}
		if !valid {
			return "", false
		}
	}
	return line, true
}
