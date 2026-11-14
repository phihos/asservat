package kubernetes

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// InitialRuntimeResources owns one fixed sequence of inert public objects.
// No arbitrary body, kind, name, API endpoint or grant is accepted by Advance.
// This component cannot create credentials, change guards, launch a process or
// establish accepted configuration. The separate bridge follows its completion.
type InitialRuntimeResources struct {
	ownerProjectionRoot *OwnerIdentityRoleRoot // first split projection lineage; guarded by mu

	preparer                    *InitialPreparer
	effects                     app.InitialRuntimeBridgeEffects
	record                      audit.InitialInstallation
	initial                     contracts.InitialInstaller
	ownerRoots                  [][]byte
	names                       initialRuntimeResourceNames
	binding, rootUID            string
	workerLayout, ownerLayout   string
	observationFormat           string
	ownerFleet                  bool
	workerProvider              *contracts.ConfigurationProviderSelection
	ownerProvider               *contracts.OwnerProviderSelection
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	closed, busy, freshRootUsed bool
	joined                      sync.WaitGroup
}

func (s *InitialRuntimeResources) name() string {
	return "asservat-runtime-resources-" + strings.ReplaceAll(s.initial.InstallationID, "-", "")
}
func (s *InitialRuntimeResources) path() string {
	return "/api/v1/namespaces/" + s.initial.Namespace.Name + "/secrets/" + s.name()
}
func (s *InitialRuntimeResources) now() time.Time { return s.preparer.protection.observer.now() }

func (s *InitialRuntimeResources) valid(v contracts.InitialRuntimeResourceState) bool {
	now := s.now()
	if v.ObservationFormat != s.observationFormat || !initialRuntimeObservationSelectionValid(v.WorkerLayout, v.OwnerLayout, v.ObservationFormat) || v.OwnerLayout != s.ownerLayout || v.WorkerLayout != s.workerLayout || !initialRuntimeProviderSelectionValid(s.initial.InstallationID, v.WorkerLayout, v.OwnerLayout, v.WorkerProvider, v.OwnerProvider) || !equalJSON(v.WorkerProvider, s.workerProvider) || !equalJSON(v.OwnerProvider, s.ownerProvider) || !ownerIdentityResourceStateValid(v, now) || v.Format != contracts.InitialRuntimeResourcesFormat || v.BindingDigest != s.binding || !authorization.UUID(v.SetupID) || v.CreatedAt.Year() < 2020 || v.CreatedAt.After(now) || !v.CreatedAt.Equal(v.CreatedAt.Truncate(time.Microsecond)) || v.Until.Sub(v.CreatedAt) != 30*time.Minute || v.Objects == nil || len(v.Objects) > contracts.InitialRuntimeResourceCount || contracts.InitialRuntimeResourceCount != len(initialRuntimeResourceItems) {
		return false
	}
	seen := map[string]bool{v.SetupID: true}
	uids := map[string]bool{}
	if v.WorkerProvider != nil {
		uids[v.WorkerProvider.AuditCredentials.UID] = true
	}
	if v.OwnerProvider != nil {
		uids[v.OwnerProvider.AuditCredentials.UID] = true
	}
	for i, c := range v.Objects {
		if c.Item != initialRuntimeResourceItems[i] || !authorization.UUID(c.OperationID) || seen[c.OperationID] || !preparationDigestValid(c.TemplateDigest) || c.ClaimedAt.Before(v.CreatedAt) || c.ClaimedAt.After(now) || !c.ClaimedAt.Equal(c.ClaimedAt.Truncate(time.Microsecond)) || !c.Until.Equal(c.Until.Truncate(time.Microsecond)) || !c.ClaimedAt.Before(c.Until) || c.Until.After(v.Until) || c.Until.Sub(c.ClaimedAt) > 5*time.Second || i > 0 && v.Objects[i-1].Receipt == nil {
			return false
		}
		seen[c.OperationID] = true
		want, e := s.object(v, i)
		if e != nil || preparationDigest(want.object) != c.TemplateDigest {
			return false
		}
		if r := c.Receipt; r != nil {
			if !authorization.UUID(r.UID) || uids[r.UID] || !identity.Text(r.ResourceVersion, 128) || r.Generation < 0 || r.Generation >= 1<<53 {
				return false
			}
			uids[r.UID] = true
		} else if i != len(v.Objects)-1 {
			return false
		}
	}
	return workerProjectionStateValid(s.initial.InstallationID, v, now)
}

func (s *InitialRuntimeResources) decode(ctx context.Context, raw []byte) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	var out contracts.InitialRuntimeResourceSnapshot
	var obj core.Secret
	if permissionJSON(raw, contracts.InitialRuntimeResourcesMaxBytes*2, 32768) != nil || strictGuardJSON(raw, &obj) != nil || obj.APIVersion != "v1" || obj.Kind != "Secret" || obj.Namespace != s.initial.Namespace.Name || obj.Name != s.name() || !authorization.UUID(string(obj.UID)) || !identity.Text(obj.ResourceVersion, 128) || obj.DeletionTimestamp != nil || len(obj.OwnerReferences) != 0 || len(obj.Finalizers) != 0 || len(obj.Labels) != 0 || len(obj.Annotations) != 0 || obj.Type != core.SecretTypeOpaque || obj.Immutable != nil && *obj.Immutable || len(obj.Data) != 1 || len(obj.StringData) != 0 {
		return out, nil, cfg.ErrChanged
	}
	v, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(obj.Data["state.json"]))
	if e != nil || !s.valid(v) {
		return out, nil, cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok || initialHandoverDeadline(ctx, s.now, until) != nil {
		return out, nil, cfg.ErrUnavailable
	}
	return contracts.InitialRuntimeResourceSnapshot{State: v, UID: string(obj.UID), ResourceVersion: obj.ResourceVersion, ValidUntil: until}, &obj, nil
}
func (s *InitialRuntimeResources) read(ctx context.Context) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	b, e := s.preparer.creator.api.Get().AbsPath(s.path()).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		return contracts.InitialRuntimeResourceSnapshot{}, nil, cfg.ErrUnavailable
	}
	return s.decode(ctx, b)
}
