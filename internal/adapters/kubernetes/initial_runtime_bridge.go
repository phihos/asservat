package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
)

const initialRuntimeBridgeMarker = "asservat.io/initial-runtime-bridge-operation"

// InitialRuntimeBridge owns exactly two fixed policy CAS operations. Its
// concrete native source is the same independently checked configuration
// producer used for the three bootstrap roles. It never edits the retired
// initial root, creates runtime credentials, starts a Pod or accepts SQL trust.
type InitialRuntimeBridge struct {
	preparer                      *InitialPreparer
	source                        *ConfigurationRoleSource
	effects                       app.InitialRuntimeBridgeEffects
	record                        audit.InitialInstallation
	administration                cfg.InitialRuntimeBridgeAdministration
	initial                       contracts.InitialInstaller
	binding, rootUID              string
	policies                      [3]*admission.ValidatingAdmissionPolicy
	guards                        [3]*configMapProtection
	ctx                           context.Context
	cancel                        context.CancelFunc
	mu                            sync.Mutex
	closed, busy, createAttempted bool
	joined                        sync.WaitGroup
}

func (s *InitialRuntimeBridge) name() string {
	return "asservat-runtime-bridge-" + strings.ReplaceAll(s.source.input.InstallationID, "-", "")
}
func (s *InitialRuntimeBridge) path() string {
	return "/api/v1/namespaces/" + s.initial.Namespace.Name + "/secrets/" + s.name()
}
func (s *InitialRuntimeBridge) policyPath() string {
	return "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + s.initial.WorkloadGuard.Name
}

func (s *InitialRuntimeBridge) deadline(ctx context.Context) error {
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.source.client.now, until)
}
func initialRuntimeBridgeSpecDigest(p *admission.ValidatingAdmissionPolicy) string {
	spec := p.Spec.DeepCopy()
	normalizePermissionPolicy(spec)
	b, _ := json.Marshal(spec)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func (s *InitialRuntimeBridge) validState(v contracts.InitialRuntimeBridgeState, now time.Time) bool {
	if v.Format != contracts.InitialRuntimeBridgeStateFormat || v.BindingDigest != s.binding || !authorization.UUID(v.SetupID) || v.CreatedAt.Year() < 2020 || v.CreatedAt.After(now) || !v.CreatedAt.Equal(v.CreatedAt.Truncate(time.Microsecond)) || v.Until.Sub(v.CreatedAt) != 30*time.Minute {
		return false
	}
	ids := map[string]bool{v.SetupID: true}
	for n, c := range []*contracts.InitialRuntimeBridgeTransition{v.Probe, v.Retained} {
		if c == nil {
			if n == 0 && v.Retained != nil {
				return false
			}
			continue
		}
		if n == 1 && (v.Probe == nil || v.Probe.Receipt == nil) {
			return false
		}
		if !authorization.UUID(c.OperationID) || ids[c.OperationID] || !identity.Text(c.FromResourceVersion, 128) || c.FromGeneration != s.guards[n].pin.PolicyGeneration || c.ClaimedAt.Before(v.CreatedAt) || c.ClaimedAt.After(now) || !c.ClaimedAt.Equal(c.ClaimedAt.Truncate(time.Microsecond)) || !c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second || c.Until.After(v.Until) {
			return false
		}
		ids[c.OperationID] = true
		if n == 1 && c.ClaimedAt.Before(v.Probe.ClaimedAt) {
			return false
		}
		if r := c.Receipt; r != nil {
			if r.PolicyUID != s.guards[n].pin.PolicyUID || r.Generation != c.FromGeneration+1 || !identity.Text(r.ResourceVersion, 128) || r.ResourceVersion == c.FromResourceVersion || r.SpecDigest != initialRuntimeBridgeSpecDigest(s.policies[n+1]) {
				return false
			}
		}
	}
	return true
}
func (s *InitialRuntimeBridge) decode(raw []byte, ctx context.Context) (contracts.InitialRuntimeBridgeSnapshot, *core.Secret, error) {
	var zero contracts.InitialRuntimeBridgeSnapshot
	var obj core.Secret
	if permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &obj) != nil || obj.APIVersion != "v1" || obj.Kind != "Secret" || obj.Namespace != s.initial.Namespace.Name || obj.Name != s.name() || !authorization.UUID(string(obj.UID)) || !identity.Text(obj.ResourceVersion, 128) || obj.DeletionTimestamp != nil || len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || obj.Type != core.SecretTypeOpaque || obj.Immutable != nil && *obj.Immutable || len(obj.Data) != 1 || len(obj.StringData) != 0 {
		return zero, nil, cfg.ErrChanged
	}
	raw, ok := obj.Data["state.json"]
	if !ok {
		return zero, nil, cfg.ErrChanged
	}
	state, err := contracts.DecodeInitialRuntimeBridgeState(bytes.NewReader(raw))
	if err != nil || !s.validState(state, s.source.client.now()) {
		return zero, nil, cfg.ErrChanged
	}
	if err = s.deadline(ctx); err != nil {
		return zero, nil, err
	}
	until, _ := ctx.Deadline()
	return contracts.InitialRuntimeBridgeSnapshot{State: state, UID: string(obj.UID), ResourceVersion: obj.ResourceVersion, ValidUntil: until}, &obj, nil
}
func (s *InitialRuntimeBridge) read(ctx context.Context) (contracts.InitialRuntimeBridgeSnapshot, *core.Secret, error) {
	raw, err := s.preparer.creator.raw(ctx, s.path(), nil)
	if err != nil {
		return contracts.InitialRuntimeBridgeSnapshot{}, nil, err
	}
	return s.decode(raw, ctx)
}
