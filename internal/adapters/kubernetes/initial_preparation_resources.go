package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const initialPreparationOperationAnnotation = "asservat.io/preparation-operation"

// InitialPreparationWorkloadDigest binds the validated, entirely public names,
// image and template selection. The later full execution plan has its own digest
// including actual object/provider pins; credentials are never hashed here.
func InitialPreparationWorkloadDigest(p InitialInstallerWorkloadPlan) (artifact.Digest, error) {
	if _, err := BuildInitialInstallerWorkload(p); err != nil {
		return artifact.Digest{}, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return artifact.Digest{}, cfg.ErrInvalid
	}
	return artifact.Digest(sha256.Sum256(b)), nil
}

type initialPreparationResource struct {
	object    runtime.Object
	path      string
	namespace string
	digest    string
}

// Only the predefined writer account and installer RBAC are supported. Probe
// bootstrap precedes this journal; Pods, Secrets and arbitrary resource bodies
// are deliberately not accepted by this producer.
type InitialPreparationResources struct {
	journal *InitialPreparationJournal
	objects map[string]initialPreparationResource
}

func NewInitialPreparationResources(journal *InitialPreparationJournal, p InitialInstallerWorkloadPlan) (*InitialPreparationResources, error) {
	digest, err := InitialPreparationWorkloadDigest(p)
	if err != nil || journal == nil || p.Namespace != journal.expected.Namespace.Name || p.Configuration != journal.creator.plan.Inputs || hex.EncodeToString(digest[:]) != journal.expected.PlanDigest {
		return nil, cfg.ErrInvalid
	}
	w, err := BuildInitialInstallerWorkload(p)
	if err != nil {
		return nil, err
	}
	s := &InitialPreparationResources{journal: journal, objects: map[string]initialPreparationResource{}}
	add := func(kind, name, namespace, group, resource string, v runtime.Object) {
		path := "/api/v1"
		if group != "" {
			path = "/apis/" + group + "/v1"
		}
		if namespace != "" {
			path += "/namespaces/" + namespace
		}
		v.GetObjectKind().SetGroupVersionKind(core.SchemeGroupVersion.WithKind(kind))
		if group != "" {
			v.GetObjectKind().SetGroupVersionKind(rbac.SchemeGroupVersion.WithKind(kind))
		}
		raw, _ := json.Marshal(v)
		d := sha256.Sum256(raw)
		s.objects[kind+"/"+name] = initialPreparationResource{v, path + "/" + resource, namespace, hex.EncodeToString(d[:])}
	}
	for _, v := range w.Accounts {
		if v.Name == p.WriterAccount {
			add("ServiceAccount", v.Name, p.Namespace, "", "serviceaccounts", v)
		}
	}
	for _, v := range w.Roles {
		add("Role", v.Name, p.Namespace, rbac.GroupName, "roles", v)
	}
	for _, v := range w.Bindings {
		add("RoleBinding", v.Name, p.Namespace, rbac.GroupName, "rolebindings", v)
	}
	add("ClusterRole", w.ClusterRole.Name, "", rbac.GroupName, "clusterroles", w.ClusterRole)
	add("ClusterRoleBinding", w.ClusterBinding.Name, "", rbac.GroupName, "clusterrolebindings", w.ClusterBinding)
	return s, nil
}

func preparationMetadata(v runtime.Object) *meta.ObjectMeta {
	switch v := v.(type) {
	case *core.ServiceAccount:
		return &v.ObjectMeta
	case *rbac.Role:
		return &v.ObjectMeta
	case *rbac.RoleBinding:
		return &v.ObjectMeta
	case *rbac.ClusterRole:
		return &v.ObjectMeta
	case *rbac.ClusterRoleBinding:
		return &v.ObjectMeta
	}
	return nil
}

func (s *InitialPreparationResources) verified(raw []byte, desired initialPreparationResource, intent contracts.InitialPreparationCreate) (contracts.InitialPreparationReceipt, error) {
	var zero contracts.InitialPreparationReceipt
	// Allocate an empty response of the expected type; never seed response
	// decoding with the desired specification or ownership markers.
	var v runtime.Object
	switch desired.object.(type) {
	case *core.ServiceAccount:
		v = new(core.ServiceAccount)
	case *rbac.Role:
		v = new(rbac.Role)
	case *rbac.RoleBinding:
		v = new(rbac.RoleBinding)
	case *rbac.ClusterRole:
		v = new(rbac.ClusterRole)
	case *rbac.ClusterRoleBinding:
		v = new(rbac.ClusterRoleBinding)
	default:
		return zero, cfg.ErrInvalid
	}
	if permissionJSON(raw, 64<<10, 8192) != nil || strictGuardJSON(raw, v) != nil {
		return zero, cfg.ErrChanged
	}
	m := preparationMetadata(v)
	if !s.journal.creator.owns(*m, intent.Name) || m.Namespace != desired.namespace || len(m.Labels) != 0 || len(m.Finalizers) != 0 || len(m.Annotations) != 3 || m.Annotations[initialPreparationOperationAnnotation] != intent.OperationID || intent.Receipt != nil && string(m.UID) != intent.Receipt.UID {
		return zero, cfg.ErrChanged
	}
	receipt := contracts.InitialPreparationReceipt{UID: string(m.UID), ResourceVersion: m.ResourceVersion}
	*m = meta.ObjectMeta{Name: intent.Name, Namespace: desired.namespace}
	if !equalJSON(v, desired.object) {
		return zero, cfg.ErrChanged
	}
	return receipt, nil
}

// Ensure executes at most one create for a newly acknowledged intent. All
// retries are exact lookups, including a lost create reply and process restart.
// A pending intent with no matching object remains unavailable, never recreated.
func (s *InitialPreparationResources) Ensure(ctx context.Context, kind, name string) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil {
		return zero, cfg.ErrInvalid
	}
	desired, ok := s.objects[kind+"/"+name]
	if !ok {
		return zero, cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	state, err := s.journal.Read(ctx)
	if err != nil {
		return zero, err
	}
	intent := contracts.InitialPreparationCreate{Kind: kind, Name: name, SpecDigest: desired.digest}
	for _, entry := range state.Creates {
		if entry.Kind == kind && entry.Name == name {
			if entry.SpecDigest != desired.digest {
				return zero, cfg.ErrChanged
			}
			intent = entry
		}
	}
	fresh := false
	if intent.OperationID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return zero, cfg.ErrUnavailable
		}
		id[6], id[8] = id[6]&15|64, id[8]&63|128
		intent.OperationID = fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
		started, err := s.journal.Begin(ctx, intent)
		if err != nil {
			return zero, err
		}
		fresh = started.Fresh
	}
	until, err := s.journal.current(ctx)
	if err != nil {
		return zero, err
	}
	var raw []byte
	if fresh {
		v := desired.object.DeepCopyObject()
		m := preparationMetadata(v)
		s.journal.creator.stamp(m)
		m.Annotations[initialPreparationOperationAnnotation] = intent.OperationID
		raw, err = s.journal.creator.post(ctx, desired.path, v)
		if errors.Is(err, cfg.ErrDenied) {
			return zero, err
		}
	}
	if !fresh || err != nil {
		raw, err = s.journal.creator.raw(ctx, desired.path+"/"+name, nil)
		if err != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	receipt, err := s.verified(raw, desired, intent)
	if err != nil {
		return zero, err
	}
	if err := s.journal.finish(ctx, until); err != nil {
		return zero, err
	}
	if intent.Receipt == nil {
		if err := s.journal.Observe(ctx, intent.OperationID, receipt); err != nil {
			return zero, err
		}
	}
	return contracts.WorkerObjectReference{Name: name, UID: receipt.UID}, nil
}
