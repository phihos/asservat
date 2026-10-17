package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InstalledWorkerProjectionReader reads only the original public resource journal and
// the dedicated projection's metadata. The latter named GET also permits the
// already-mounted dedicated payload under native RBAC; Accept is not an ACL.
// It never opens the private role root or accepts file existence as activation.
type InstalledWorkerProjectionReader struct {
	client *PermissionClient
	guard  *OwnerWorkloadProtection
	input  contracts.HubWorkerDeployment
}

func NewInstalledWorkerProjectionReader(client, probe *PermissionClient, input contracts.HubWorkerDeployment) (*InstalledWorkerProjectionReader, error) {
	if client == nil || probe == nil || client == probe || client.clusterID != input.ClusterID || client.control != (cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}) || !HubWorkerActivationBound(input) {
		return nil, cfg.ErrInvalid
	}
	a := input.Activation
	want := capacityActivationAdministration(input)
	pin := GuardPin{PolicyUID: a.WorkloadGuard.PolicyUID, PolicyGeneration: a.WorkloadGuard.PolicyGeneration, BindingUID: a.WorkloadGuard.BindingUID, BindingResourceVersion: a.WorkloadGuard.BindingResourceVersion}
	guard, e := NewOwnerWorkloadProtection(client, probe, want, pin)
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(input)
	var pinned contracts.HubWorkerDeployment
	if e != nil || json.Unmarshal(b, &pinned) != nil {
		return nil, cfg.ErrInvalid
	}
	// Decoding into the existing shallow copy would reuse nested pointers and
	// slices, allowing the caller to change this reader's original input pins.
	return &InstalledWorkerProjectionReader{client: client, guard: guard, input: pinned}, nil
}

func capacityActivationAdministration(in contracts.HubWorkerDeployment) cfg.OwnerWorkloadAdministration {
	a := in.Activation
	p := cfg.OwnerWorkloadAdministration{Name: a.WorkloadGuard.Name, Deployment: a.OwnerDeployment.Name, DeploymentUID: a.OwnerDeployment.UID, ControlNamespace: cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}}
	for _, v := range a.WorkloadGuard.Administrators {
		p.Administrators = append(p.Administrators, cfg.KubernetesActor{Kind: v.Kind, Name: v.Name})
	}
	for _, v := range a.ConfigurationProbes {
		p.ConfigurationProbes = append(p.ConfigurationProbes, cfg.OwnerConfigurationProbe{ConfigMap: v.ConfigMap, ServiceAccount: v.ServiceAccount})
	}
	for _, v := range a.SchedulingLeases {
		p.SchedulingLeases = append(p.SchedulingLeases, cfg.OwnerSchedulingLease{Lease: v.Lease, ServiceAccount: v.ServiceAccount})
	}
	if a.CapacityProbe != nil {
		p.CapacityProbe = &cfg.OwnerCapacityProbe{ServiceAccount: a.CapacityProbe.ServiceAccount.Name, ServiceAccountUID: a.CapacityProbe.ServiceAccount.UID}
	}
	h := a.InitialHistoryProbe
	p.InitialHistoryProbe = &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: h.Namespace.Name, UID: h.Namespace.UID}, ServiceAccount: h.ServiceAccount.Name, ServiceAccountUID: h.ServiceAccount.UID, Configuration: h.Configuration}
	return p
}

// ReadCapacity returns pending only after a successful current read. Neither
// an unavailable journal nor file existence can become a positive receipt.
func (s *InstalledWorkerProjectionReader) ReadCapacity(ctx context.Context) (contracts.CapacityRuntimeProjectionClaim, bool, time.Time, error) {
	var zero contracts.CapacityRuntimeProjectionClaim
	call, end, state, until, err := s.beginObservation(ctx)
	if err != nil {
		return zero, false, time.Time{}, err
	}
	defer end()
	p := state.CapacityProjection
	if p != nil && p.Receipt != nil {
		r := p.Receipt
		if err = s.projectionMetadata(call, state.SetupID, p.OperationID, p.PublicDigest, r.Secret, r.ResourceVersion); err != nil {
			return zero, false, time.Time{}, err
		}
	} else {
		until = identity.Earlier(until, state.Until)
	}
	until, err = s.finishObservation(call, until)
	if err != nil {
		return zero, false, time.Time{}, err
	}
	if p == nil || p.Receipt == nil {
		return zero, false, until, nil
	}
	return *p, true, until, nil
}

// Shared only by the two fixed capacity/cleanup methods. This reads no private
// role journal and cannot select a credential, effect or arbitrary subsystem.
func (s *InstalledWorkerProjectionReader) beginObservation(ctx context.Context) (context.Context, context.CancelFunc, contracts.InitialRuntimeResourceState, time.Time, error) {
	var zero contracts.InitialRuntimeResourceState
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, zero, time.Time{}, cfg.ErrUnavailable
	}
	started := s.client.now()
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	ok := false
	defer func() {
		if !ok {
			end()
		}
	}()
	until, _ := call.Deadline()
	_, bound, err := s.guard.Current(call)
	if err != nil {
		return nil, nil, zero, time.Time{}, err
	}
	until = identity.Earlier(until, bound)
	live, narrow := context.WithDeadline(call, until)
	finish := func() { narrow(); end() }
	if err = s.identity(live); err != nil {
		narrow()
		return nil, nil, zero, time.Time{}, err
	}
	state, err := s.journal(live)
	if err != nil {
		narrow()
		return nil, nil, zero, time.Time{}, err
	}
	if err = s.workload(live, state); err != nil {
		narrow()
		return nil, nil, zero, time.Time{}, err
	}
	if err = initialHandoverDeadline(live, s.client.now, until); err != nil {
		narrow()
		return nil, nil, zero, time.Time{}, err
	}
	ok = true
	return live, finish, state, until, nil
}

func (s *InstalledWorkerProjectionReader) finishObservation(ctx context.Context, until time.Time) (time.Time, error) {
	live, end := context.WithDeadline(ctx, until)
	defer end()
	if err := initialHandoverDeadline(live, s.client.now, until); err != nil {
		return time.Time{}, err
	}
	_, bound, err := s.guard.Current(live)
	if err != nil {
		return time.Time{}, err
	}
	until = identity.Earlier(until, bound)
	if err = initialHandoverDeadline(live, s.client.now, until); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

func (s *InstalledWorkerProjectionReader) identity(ctx context.Context) error {
	raw, e := s.client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if e != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.input.Namespace.Name+":"+s.input.Activation.ServiceAccount.Name {
		return cfg.ErrDenied
	}
	return nil
}

func (s *InstalledWorkerProjectionReader) get(ctx context.Context, path string, out any) error {
	raw, e := s.client.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return cfg.ErrUnavailable
	}
	if permissionJSON(raw, contracts.InitialRuntimeResourcesMaxBytes*2, 32768) != nil || strictGuardJSON(raw, out) != nil {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}

func (s *InstalledWorkerProjectionReader) journal(ctx context.Context) (contracts.InitialRuntimeResourceState, error) {
	var zero contracts.InitialRuntimeResourceState
	a := s.input.Activation
	var object core.Secret
	if e := s.get(ctx, "/api/v1/namespaces/"+s.input.Namespace.Name+"/secrets/"+a.Resources.Name, &object); e != nil {
		return zero, e
	}
	defer clearRuntimeProjection(object.Data)
	if object.APIVersion != "v1" || object.Kind != "Secret" || !ownerMetadata(object.ObjectMeta, s.input.Namespace.Name, a.Resources.Name, a.Resources.UID) ||
		len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.Labels) != 0 || len(object.Annotations) != 0 || object.Type != core.SecretTypeOpaque ||
		object.Immutable != nil && *object.Immutable || len(object.StringData) != 0 || len(object.Data) != 1 {
		return zero, cfg.ErrChanged
	}
	v, e := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(object.Data["state.json"]))
	if e != nil || v.Format != contracts.InitialRuntimeResourcesFormat || v.SetupID != a.SetupID || v.BindingDigest != a.BindingDigest || v.WorkerLayout != a.WorkerLayout ||
		!v.CreatedAt.Equal(a.CreatedAt) || !v.Until.Equal(a.Until) || len(v.Objects) != len(initialRuntimeResourceItems) || !workerProjectionStateValid(s.input.InstallationID, v, s.client.now()) {
		return zero, cfg.ErrChanged
	}
	ids := map[string]bool{v.SetupID: true}
	uids := map[string]bool{a.Resources.UID: true}
	for i, c := range v.Objects {
		if c.Item != initialRuntimeResourceItems[i] || !authorization.UUID(c.OperationID) || ids[c.OperationID] || !preparationDigestValid(c.TemplateDigest) ||
			c.ClaimedAt.Before(v.CreatedAt) || c.ClaimedAt.After(s.client.now()) || !capacityProjectionMicrotime(c.ClaimedAt) || !capacityProjectionMicrotime(c.Until) ||
			!c.Until.After(c.ClaimedAt) || c.Until.Sub(c.ClaimedAt) > 5*time.Second || c.Until.After(v.Until) || c.Receipt == nil || !authorization.UUID(c.Receipt.UID) ||
			uids[c.Receipt.UID] || !identity.Text(c.Receipt.ResourceVersion, 128) || c.Receipt.Generation < 0 || c.Receipt.Generation >= 1<<53 {
			return zero, cfg.ErrChanged
		}
		ids[c.OperationID], uids[c.Receipt.UID] = true, true
	}
	if v.Objects[1].Receipt.UID != a.ServiceAccount.UID || v.Objects[10].Receipt.UID != a.OwnerDeployment.UID || v.Objects[11].Receipt.UID != a.Deployment.UID || v.Objects[13].Receipt.UID != s.input.LeaderLease.UID {
		return zero, cfg.ErrChanged
	}
	return v, nil
}
