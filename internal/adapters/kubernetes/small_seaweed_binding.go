package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// SmallSeaweedBinding is one cold installation intent. It has no list, delete,
// adoption, watch, credential generation or runtime authorization behavior.
type SmallSeaweedBinding struct {
	api  rest.Interface
	plan contracts.SmallSeaweedPlan
	now  func() time.Time
}

var smallSeaweedBindingBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func NewSmallSeaweedBinding(config *rest.Config, plan contracts.SmallSeaweedPlan) (*SmallSeaweedBinding, error) {
	if !plan.Valid() {
		return nil, cfg.ErrInvalid
	}
	api, e := newBoundedAPI(config)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	return &SmallSeaweedBinding{api: api, plan: plan, now: time.Now}, nil
}
func (s *SmallSeaweedBinding) name() string { return s.plan.ServiceName() + "-binding" }
func (s *SmallSeaweedBinding) path() string {
	return "/api/v1/namespaces/" + s.plan.Namespace + "/configmaps/" + s.name()
}
func smallSeaweedBindingRequestValid(r contracts.SmallSeaweedBindingRequest) bool {
	return authorization.UUID(r.InstallationID) && authorization.UUID(r.RequestID) && smallSeaweedBindingBucket.MatchString(r.Bucket) && !strings.Contains(r.Bucket, "..") && r.StorageUseUntil.Year() >= 2020 && r.StorageUseUntil.Year() < 9999
}
func (s *SmallSeaweedBinding) current(ctx context.Context, r contracts.SmallSeaweedBindingRequest) bool {
	if s == nil || ctx == nil || ctx.Err() != nil || !smallSeaweedBindingRequestValid(r) {
		return false
	}
	now := s.now()
	if !now.Before(r.StorageUseUntil) {
		return false
	}
	until, bounded := ctx.Deadline()
	return !bounded || now.Before(until)
}
func smallSeaweedBindingRequest(b contracts.SmallSeaweedBinding) contracts.SmallSeaweedBindingRequest {
	return contracts.SmallSeaweedBindingRequest{InstallationID: b.Initialization.InstallationID, RequestID: b.RequestID, Bucket: b.Initialization.Bucket, StorageUseUntil: b.StorageUseUntil}
}
func sameSmallSeaweedBinding(a, b contracts.SmallSeaweedBinding) bool {
	a.Initialization.Pending = true
	b.Initialization.Pending = true
	a.StorageUseUntil = a.StorageUseUntil.UTC()
	b.StorageUseUntil = b.StorageUseUntil.UTC()
	return a == b
}
func (s *SmallSeaweedBinding) valid(b contracts.SmallSeaweedBinding) bool {
	i := b.Initialization
	if b.Format != contracts.SmallSeaweedBindingFormat || !smallSeaweedBindingRequestValid(smallSeaweedBindingRequest(b)) || i.Endpoint != s.plan.Endpoint() || i.Image != s.plan.Image {
		return false
	}
	for _, id := range []string{i.BackendID, i.InitializationID, i.StateSecretUID, i.PVCUID, b.IAMSecretUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return true
}
func (s *SmallSeaweedBinding) decode(raw []byte) (*core.ConfigMap, contracts.SmallSeaweedBinding, error) {
	var cm core.ConfigMap
	var zero contracts.SmallSeaweedBinding
	if len(raw) > 2*contracts.SmallSeaweedBindingMaxBytes || strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Name != s.name() || cm.Namespace != s.plan.Namespace || !authorization.UUID(string(cm.UID)) || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 0 || len(cm.Finalizers) != 0 || len(cm.Annotations) != 0 || len(cm.Labels) != 1 || cm.Labels["asservat.io/private-role"] != "small-seaweed-binding" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.Immutable != nil && *cm.Immutable {
		return nil, zero, seaweedProviderFailure("binding-record")
	}
	b, e := contracts.DecodeSmallSeaweedBinding(strings.NewReader(cm.Data[contracts.SmallSeaweedBindingFile]))
	if e != nil || !s.valid(b) {
		return nil, zero, seaweedProviderFailure("binding-data")
	}
	return &cm, b, nil
}
func (s *SmallSeaweedBinding) read(ctx context.Context) (*core.ConfigMap, contracts.SmallSeaweedBinding, error) {
	raw, e := s.api.Get().AbsPath(s.path()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return nil, contracts.SmallSeaweedBinding{}, e
	}
	return s.decode(raw)
}
func smallSeaweedBindingReceipt(cm *core.ConfigMap, b contracts.SmallSeaweedBinding) contracts.SmallSeaweedBindingReceipt {
	return contracts.SmallSeaweedBindingReceipt{Binding: b, ConfigMap: contracts.WorkerObjectReference{Name: cm.Name, UID: string(cm.UID)}, ResourceVersion: cm.ResourceVersion}
}

// sourceCurrent checks the existing caller deadline; it creates no deadline
// and has no knowledge of an initial storage authorization interval.
func (s *SmallSeaweedBinding) sourceCurrent(ctx context.Context) bool {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	until, bounded := ctx.Deadline()
	return bounded && s.now().Before(until)
}

// observe is the initial-operation consumer: provenance alone never bypasses
// its original StorageUseUntil, including after a blocking source read.
func (s *SmallSeaweedBinding) observe(ctx context.Context, r contracts.SmallSeaweedBindingRequest) (contracts.SmallSeaweedBinding, contracts.SmallSeaweedPrepared, bool, error) {
	if !s.current(ctx, r) {
		return contracts.SmallSeaweedBinding{}, contracts.SmallSeaweedPrepared{}, false, seaweedProviderFailure("binding-expired")
	}
	b, p, only, err := s.observeSources(ctx, r)
	if err != nil {
		return b, p, only, err
	}
	if !s.current(ctx, r) {
		clear(p.RootsPEM)
		return contracts.SmallSeaweedBinding{}, contracts.SmallSeaweedPrepared{}, false, seaweedProviderFailure("binding-expired")
	}
	return b, p, only, nil
}

// observeSources reads named state/IAM/PVC provenance under the caller's
// original bounded context. It does not consume or renew initial authority.
func (s *SmallSeaweedBinding) observeSources(ctx context.Context, r contracts.SmallSeaweedBindingRequest) (contracts.SmallSeaweedBinding, contracts.SmallSeaweedPrepared, bool, error) {
	var zero contracts.SmallSeaweedBinding
	var none contracts.SmallSeaweedPrepared
	if !s.sourceCurrent(ctx) {
		return zero, none, false, seaweedProviderFailure("binding-source-context")
	}
	source := &SmallSeaweedPreparation{api: s.api, plan: s.plan, now: s.now}
	state, e := source.readSecret(ctx, s.plan.StateSecretName())
	if e != nil {
		return zero, none, false, seaweedProviderFailure("binding-state")
	}
	defer clearSmallSeaweedData(state.Data)
	if !s.sourceCurrent(ctx) || !source.validState(state) {
		return zero, none, false, seaweedProviderFailure("binding-state")
	}
	admin, e := decodeSmallSeaweedAdmin(state.Data[contracts.SmallSeaweedAdminKey])
	if e != nil {
		return zero, none, false, seaweedProviderFailure("binding-admin")
	}
	initial, e := providerconfig.CompileSeaweedStorage(admin, nil)
	if e != nil {
		return zero, none, false, seaweedProviderFailure("binding-admin")
	}
	defer clear(initial.Config)
	if !s.sourceCurrent(ctx) {
		return zero, none, false, seaweedProviderFailure("binding-source-context")
	}
	iam, e := source.readSecret(ctx, s.plan.IAMSecretName())
	if e != nil {
		return zero, none, false, seaweedProviderFailure("binding-iam")
	}
	defer clearSmallSeaweedData(iam.Data)
	if !s.sourceCurrent(ctx) || !source.validIAM(iam, state, initial.Config) {
		return zero, none, false, seaweedProviderFailure("binding-iam")
	}
	if !s.sourceCurrent(ctx) {
		return zero, none, false, seaweedProviderFailure("binding-source-context")
	}
	raw, e := s.api.Get().AbsPath("/api/v1/namespaces/" + s.plan.Namespace + "/persistentvolumeclaims/" + s.plan.DataPVCName()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var pvc core.PersistentVolumeClaim
	if e != nil || len(raw) > 64<<10 || strictGuardJSON(raw, &pvc) != nil || pvc.APIVersion != "v1" || pvc.Kind != "PersistentVolumeClaim" || pvc.Name != s.plan.DataPVCName() || pvc.Namespace != s.plan.Namespace || !authorization.UUID(string(pvc.UID)) || pvc.ResourceVersion == "" || pvc.DeletionTimestamp != nil {
		return zero, none, false, seaweedProviderFailure("binding-pvc")
	}
	if !s.sourceCurrent(ctx) {
		return zero, none, false, seaweedProviderFailure("binding-expired")
	}
	b := contracts.SmallSeaweedBinding{Format: contracts.SmallSeaweedBindingFormat, RequestID: r.RequestID, Initialization: contracts.SeaweedBucketInitialization{BackendID: string(state.Data[contracts.SmallSeaweedBackendKey]), InstallationID: r.InstallationID, InitializationID: string(state.Data[contracts.SmallSeaweedInitializationKey]), StateSecretUID: string(state.UID), PVCUID: string(pvc.UID), Endpoint: s.plan.Endpoint(), Image: s.plan.Image, Bucket: r.Bucket, Pending: true}, IAMSecretUID: string(iam.UID), StorageUseUntil: r.StorageUseUntil.UTC()}
	p := contracts.SmallSeaweedPrepared{State: contracts.WorkerObjectReference{Name: state.Name, UID: string(state.UID)}, IAM: contracts.WorkerObjectReference{Name: iam.Name, UID: string(iam.UID)}, BackendID: b.Initialization.BackendID, InitializationID: b.Initialization.InitializationID, RootsPEM: bytes.Clone(state.Data["ca.crt"]), Admin: admin}
	return b, p, bytes.Equal(initial.Config, iam.Data[providerconfig.SeaweedConfigKey]), nil
}

func (s *SmallSeaweedBinding) Begin(ctx context.Context, r contracts.SmallSeaweedBindingRequest) (contracts.SmallSeaweedBindingReceipt, contracts.SmallSeaweedPrepared, error) {
	var zero contracts.SmallSeaweedBindingReceipt
	var none contracts.SmallSeaweedPrepared
	if !s.current(ctx, r) {
		return zero, none, seaweedProviderFailure("binding-input")
	}
	ctx, end := context.WithDeadline(ctx, r.StorageUseUntil)
	defer end()
	cm, stored, e := s.read(ctx)
	fresh := apierrors.IsNotFound(e)
	if !s.current(ctx, r) || e != nil && !fresh {
		return zero, none, seaweedProviderFailure("binding-read")
	}
	if !fresh {
		wanted := smallSeaweedBindingRequest(stored)
		if wanted.InstallationID != r.InstallationID || wanted.RequestID != r.RequestID || wanted.Bucket != r.Bucket || !wanted.StorageUseUntil.Equal(r.StorageUseUntil) {
			return zero, none, seaweedProviderFailure("binding-parent")
		}
	}
	wanted, p, adminOnly, e := s.observe(ctx, r)
	if e != nil {
		return zero, none, e
	}
	fail := func(step string) (contracts.SmallSeaweedBindingReceipt, contracts.SmallSeaweedPrepared, error) {
		clear(p.RootsPEM)
		return zero, none, seaweedProviderFailure(step)
	}
	if !fresh {
		if !s.current(ctx, r) || !sameSmallSeaweedBinding(wanted, stored) || stored.Initialization.Pending && !adminOnly {
			return fail("binding-source")
		}
		return smallSeaweedBindingReceipt(cm, stored), p, nil
	}
	if !adminOnly {
		return fail("binding-writers-enabled")
	}
	data, e := json.Marshal(wanted)
	if e != nil {
		return fail("binding-encoding")
	}
	request := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: s.name(), Namespace: s.plan.Namespace, Labels: map[string]string{"asservat.io/private-role": "small-seaweed-binding"}}, Data: map[string]string{contracts.SmallSeaweedBindingFile: string(data)}}
	body, e := json.Marshal(request)
	if e != nil {
		return fail("binding-encoding")
	}
	if !s.current(ctx, r) {
		return fail("binding-expired")
	}
	raw, createErr := s.api.Post().AbsPath("/api/v1/namespaces/"+s.plan.Namespace+"/configmaps").Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	unknown := createErr != nil
	if !unknown {
		cm, stored, e = s.decode(raw)
		unknown = e != nil
	}
	if unknown {
		if !s.current(ctx, r) {
			return fail("binding-expired")
		}
		cm, stored, e = s.read(ctx)
	}
	if e != nil || !sameSmallSeaweedBinding(wanted, stored) || !s.current(ctx, r) {
		return fail("binding-create")
	}
	if !unknown && !stored.Initialization.Pending {
		return fail("binding-create-state")
	}
	if unknown {
		observed, current, only, e := s.observe(ctx, r)
		if e != nil {
			clear(current.RootsPEM)
			return fail("binding-create-source")
		}
		if !sameSmallSeaweedBinding(observed, stored) || stored.Initialization.Pending && !only {
			clear(current.RootsPEM)
			return fail("binding-create-source")
		}
		clear(p.RootsPEM)
		p = current
	}
	if !s.current(ctx, r) {
		return fail("binding-expired")
	}
	return smallSeaweedBindingReceipt(cm, stored), p, nil
}

// MarkReady changes only the original pending bit after the caller's exact S3
// setup checks. Unknown replies permit one exact GET; positive same-UID ready
// readback plus current original sources acknowledges completion, never renewal.
func (s *SmallSeaweedBinding) MarkReady(ctx context.Context, receipt contracts.SmallSeaweedBindingReceipt) (contracts.SmallSeaweedBindingReceipt, error) {
	var zero contracts.SmallSeaweedBindingReceipt
	if s == nil || receipt.ConfigMap.Name != s.name() || !authorization.UUID(receipt.ConfigMap.UID) || receipt.ResourceVersion == "" || !s.valid(receipt.Binding) {
		return zero, seaweedProviderFailure("binding-ready-input")
	}
	r := smallSeaweedBindingRequest(receipt.Binding)
	if !s.current(ctx, r) {
		return zero, seaweedProviderFailure("binding-expired")
	}
	ctx, end := context.WithDeadline(ctx, r.StorageUseUntil)
	defer end()
	cm, stored, e := s.read(ctx)
	if e != nil || !s.current(ctx, r) || string(cm.UID) != receipt.ConfigMap.UID || !sameSmallSeaweedBinding(stored, receipt.Binding) {
		return zero, seaweedProviderFailure("binding-ready-record")
	}
	observed, p, adminOnly, e := s.observe(ctx, r)
	clear(p.RootsPEM)
	if e != nil || !sameSmallSeaweedBinding(observed, stored) || stored.Initialization.Pending && !adminOnly {
		return zero, seaweedProviderFailure("binding-ready-source")
	}
	if !stored.Initialization.Pending {
		if !s.current(ctx, r) {
			return zero, seaweedProviderFailure("binding-expired")
		}
		return smallSeaweedBindingReceipt(cm, stored), nil
	}
	if !receipt.Binding.Initialization.Pending || cm.ResourceVersion != receipt.ResourceVersion {
		return zero, seaweedProviderFailure("binding-ready-cas")
	}
	stored.Initialization.Pending = false
	data, e := json.Marshal(stored)
	if e != nil {
		return zero, seaweedProviderFailure("binding-encoding")
	}
	cm.Data[contracts.SmallSeaweedBindingFile] = string(data)
	body, e := json.Marshal(cm)
	if e != nil {
		return zero, seaweedProviderFailure("binding-encoding")
	}
	if !s.current(ctx, r) {
		return zero, seaweedProviderFailure("binding-expired")
	}
	raw, writeErr := s.api.Put().AbsPath(s.path()).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var actual *core.ConfigMap
	var ready contracts.SmallSeaweedBinding
	unknown := writeErr != nil
	if !unknown {
		actual, ready, e = s.decode(raw)
		unknown = e != nil
	}
	if unknown {
		if !s.current(ctx, r) {
			return zero, seaweedProviderFailure("binding-expired")
		}
		actual, ready, e = s.read(ctx)
	}
	if e != nil || string(actual.UID) != receipt.ConfigMap.UID || ready.Initialization.Pending || !sameSmallSeaweedBinding(ready, stored) || !s.current(ctx, r) {
		return zero, seaweedProviderFailure("binding-ready-answer")
	}
	if unknown {
		observed, p, _, e := s.observe(ctx, r)
		clear(p.RootsPEM)
		if e != nil || !sameSmallSeaweedBinding(observed, ready) || !s.current(ctx, r) {
			return zero, seaweedProviderFailure("binding-ready-unknown-source")
		}
	}
	if !s.current(ctx, r) {
		return zero, seaweedProviderFailure("binding-expired")
	}
	return smallSeaweedBindingReceipt(actual, ready), nil
}

// ReadReady observes the original completed bucket/source binding. Historical
// StorageUseUntil is returned unchanged and may be expired. This method grants
// no initial setup, provider effect, activation or recovery authority.
func (s *SmallSeaweedBinding) ReadReady(ctx context.Context, installationID, requestID, bucket string) (contracts.SmallSeaweedBindingReceipt, contracts.SmallSeaweedPrepared, error) {
	var zero contracts.SmallSeaweedBindingReceipt
	var none contracts.SmallSeaweedPrepared
	if !s.sourceCurrent(ctx) || !authorization.UUID(installationID) || !authorization.UUID(requestID) || !smallSeaweedBindingBucket.MatchString(bucket) || strings.Contains(bucket, "..") {
		return zero, none, seaweedProviderFailure("binding-ready-read-input")
	}
	cm, stored, err := s.read(ctx)
	if err != nil || !s.sourceCurrent(ctx) || stored.Initialization.Pending || stored.Initialization.InstallationID != installationID || stored.RequestID != requestID || stored.Initialization.Bucket != bucket {
		return zero, none, seaweedProviderFailure("binding-ready-read-record")
	}
	observed, prepared, _, err := s.observeSources(ctx, smallSeaweedBindingRequest(stored))
	if err != nil || !s.sourceCurrent(ctx) || !sameSmallSeaweedBinding(observed, stored) {
		clear(prepared.RootsPEM)
		return zero, none, seaweedProviderFailure("binding-ready-read-source")
	}
	return smallSeaweedBindingReceipt(cm, stored), prepared, nil
}
