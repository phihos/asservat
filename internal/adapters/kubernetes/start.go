package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	api "asservat.local/asservat/api/v1alpha1"
	port "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

const localStartProfile = "onTriggerStart/v1"
const apiContextStartProfile = "apiContextStart/v1"

type StartJournal struct {
	api       rest.Interface
	clusterID string
	control   configuration.NamespaceRef
	now       func() time.Time
}

var _ port.StartJournal = (*StartJournal)(nil)

func NewStartJournal(config *rest.Config, clusterID string, control configuration.NamespaceRef, now func() time.Time) (*StartJournal, error) {
	if !authorization.UUID(clusterID) || !namespaceRefValid(control) || now == nil {
		return nil, value.ErrInvalid
	}
	c, err := newBoundedAPI(config)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &StartJournal{api: c, clusterID: clusterID, control: control, now: now}, nil
}

// LocalStartSpec converts validated internal facts for the capacity writer. The
// journal itself cannot create, mark Ready, delete or refund a reservation.
func LocalStartSpec(b value.Binding) (api.LocalStartSpec, error) {
	if !b.Valid() {
		return api.LocalStartSpec{}, value.ErrInvalid
	}
	profile := localStartProfile
	if b.ExecutionClass == artifact.ContextAPIExecution {
		profile = apiContextStartProfile
	}
	return api.LocalStartSpec{Profile: profile, ExecutorPodUID: b.ExecutorPodUID, ExecutorAccountUID: b.ExecutorAccountUID, OperationID: b.OperationID, CaptureID: b.CaptureID, ActionID: b.ActionID, AttemptID: b.AttemptID, ClusterID: b.ClusterID, IssuerEpoch: b.IssuerEpoch, PodUID: b.PodUID, NodeUID: b.NodeUID, NodeBootID: b.NodeBootID, CollectorEpoch: b.CollectorEpoch, ScopeDigest: hex.EncodeToString(b.ScopeDigest[:]), AuthorityDigest: hex.EncodeToString(b.AuthorityDigest[:]), BudgetDigest: hex.EncodeToString(b.BudgetDigest[:]), AuditDigest: hex.EncodeToString(b.AuditDigest[:]), NativeBytes: b.NativeBytes, NotBefore: b.NotBefore.Format(time.RFC3339Nano), NotAfter: b.NotAfter.Format(time.RFC3339Nano)}, nil
}

func startError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return value.ErrDenied
	}
	if apierrors.IsConflict(err) {
		return value.ErrConflict
	}
	return value.ErrUnavailable // Missing state never means a free start.
}

type startObject struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   json.RawMessage       `json:"metadata"`
	Spec       api.LocalStartSpec    `json:"spec"`
	Status     *api.LocalStartStatus `json:"status,omitempty"`
}

func decodeStart(raw []byte, r value.Request, namespace string) (startObject, value.Disposition, error) {
	var o startObject
	var d value.Disposition
	if permissionJSON(raw, 16<<10, 2048) != nil {
		return o, d, value.ErrUnavailable
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&o) != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "CapacityReservation" {
		return o, d, value.ErrUnavailable
	}
	// encoding/json permits case-insensitive field names; the authority wire
	// contract does not. Compare exact keys, leaving Kubernetes metadata open.
	canonical, err := json.Marshal(o)
	if err != nil || !startKeys(raw, canonical, true) {
		return o, d, value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, false)
	if err != nil || m.Name != "start-"+r.Binding.AttemptID || m.Namespace != namespace || m.UID != r.ObjectUID || m.Generation != 1 {
		return o, d, value.ErrConflict
	}
	// A deletion in progress, including an object held by a finalizer, is never
	// a new-start source. No ownerReference may garbage-collect the spend record.
	var meta struct {
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		OwnerReferences   []json.RawMessage `json:"ownerReferences"`
	}
	if json.Unmarshal(o.Metadata, &meta) != nil || meta.DeletionTimestamp != nil || len(meta.OwnerReferences) > 0 {
		return o, d, value.ErrUnavailable
	}
	expected, err := LocalStartSpec(r.Binding)
	if err != nil || o.Spec != expected {
		return o, d, value.ErrConflict
	}
	if o.Status == nil {
		return o, d, value.ErrUnavailable
	}
	d.ObjectUID, d.ResourceVersion, d.Phase = m.UID, m.RV, value.Phase(o.Status.Phase)
	switch d.Phase {
	case value.Ready:
		if o.Status.CommittedAt != "" {
			return o, d, value.ErrUnavailable
		}
	case value.StartCommitted:
		t, err := time.Parse(time.RFC3339Nano, o.Status.CommittedAt)
		if err != nil || t.UTC().Format(time.RFC3339Nano) != o.Status.CommittedAt || t.Before(r.Binding.NotBefore) || !t.Before(r.Binding.NotAfter) {
			return o, d, value.ErrUnavailable
		}
		d.CommittedAt = t.UTC()
	default:
		return o, d, value.ErrUnavailable
	}
	return o, d, nil
}

func startKeys(raw, expected []byte, envelope bool) bool {
	var a, b map[string]json.RawMessage
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(expected, &b) != nil || len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
		if envelope && (key == "spec" || key == "status") && !startKeys(a[key], b[key], false) {
			return false
		}
	}
	return true
}

func (j *StartJournal) read(ctx context.Context, r value.Request) (startObject, value.Disposition, error) {
	var o startObject
	var d value.Disposition
	if !r.Binding.Valid() || !authorization.UUID(r.ObjectUID) || r.Binding.ClusterID != j.clusterID {
		return o, d, value.ErrInvalid
	}
	// Check the control namespace identity using this role's fixed GET. Name
	// reuse cannot silently attach a journal from a recreated namespace.
	raw, err := j.api.Get().AbsPath("/api/v1/namespaces/" + j.control.Name).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return o, d, startError(ctx, err)
	}
	if permissionJSON(raw, permissionPageBytes, 131072) != nil {
		return o, d, value.ErrUnavailable
	}
	ns, err := objectEnvelope(raw)
	if err != nil || ns.APIVersion != "v1" || ns.Kind != "Namespace" {
		return o, d, value.ErrUnavailable
	}
	m, err := decodeMetadata(ns.Metadata, true)
	if err != nil || m.Name != j.control.Name || m.UID != j.control.UID || m.Deleting {
		return o, d, value.ErrConflict
	}
	raw, err = j.api.Get().AbsPath(j.path(r)).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return o, d, startError(ctx, err)
	}
	return decodeStart(raw, r, j.control.Name)
}
func (j *StartJournal) path(r value.Request) string {
	return "/apis/asservat.io/v1alpha1/namespaces/" + j.control.Name + "/capacityreservations/start-" + r.Binding.AttemptID
}

func (j *StartJournal) LookupStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, d, err := j.read(ctx, r)
	// Lookup is permitted after the start deadline for reconciliation, but has
	// no start allowance. Its caller still authenticates current peer identity.
	return d, err
}

func (j *StartJournal) ConsumeStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.Validate(j.now()); err != nil {
		return value.Disposition{}, err
	}
	o, d, err := j.read(ctx, r)
	if err != nil {
		return d, err
	}
	if d.Phase == value.StartCommitted {
		return d, nil
	}
	now := j.now().UTC().Truncate(time.Microsecond)
	if err = r.Validate(now); err != nil {
		return d, err
	}
	// Supply the exact resourceVersion and UID read above. No retries on PUT:
	// lost replies and conflicts are resolved by non-authorizing lookup.
	o.Status = &api.LocalStartStatus{Phase: string(value.StartCommitted), CommittedAt: now.Format(time.RFC3339Nano)}
	payload, err := json.Marshal(o)
	if err != nil {
		return d, value.ErrInvalid
	}
	raw, err := j.api.Put().AbsPath(j.path(r) + "/status").MaxRetries(0).Body(payload).DoRaw(ctx)
	if err != nil {
		return d, startError(ctx, err)
	}
	_, committed, err := decodeStart(raw, r, j.control.Name)
	if err != nil {
		return value.Disposition{}, err
	}
	if committed.Phase != value.StartCommitted || !committed.CommittedAt.Equal(now) || committed.ResourceVersion == d.ResourceVersion {
		return value.Disposition{}, value.ErrUnavailable
	}
	// A successful write may already be too old to start by the time it arrives.
	// Keep it consumed and return no allowance; never roll the record back.
	if ctx.Err() != nil {
		return committed, ctx.Err()
	}
	if err = r.Validate(j.now()); err != nil {
		return committed, err
	}
	committed.MayStart = true
	committed.ValidUntil = identity.Earlier(r.ValidUntil, r.Binding.NotAfter)
	return committed, nil
}
