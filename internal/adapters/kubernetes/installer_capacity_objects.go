package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// EnsureInstallerCapacityObjects creates the two declared initial capacity
// sources under the existing protected installer administrator. It grants no
// capacity: the ordinary guard, source acceptance and SQL compiler still run.
// It adds no runtime task or authority state. One call uses at most two namespace
// GETs, two source GETs and two CREATEs; no update, adoption or API retry follows.
func EnsureInstallerCapacityObjects(ctx context.Context, config *rest.Config, control cfg.NamespaceRef, installation, cluster string, settings contracts.InstallerCapacitySettings) error {
	if settings.PoolSpec == nil && settings.PolicySpec == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || settings.PoolSpec == nil || settings.PolicySpec == nil ||
		!authorization.UUID(installation) || !authorization.UUID(cluster) || !authorization.UUID(control.UID) || len(validation.IsDNS1123Label(control.Name)) != 0 ||
		len(validation.IsDNS1123Label(settings.Pool)) != 0 || len(validation.IsDNS1123Label(settings.Policy)) != 0 {
		return cfg.ErrInvalid
	}
	// Clone through the exact typed wire shapes; the caller's original input and
	// replay digest retain the empty scope rather than a generated runtime pin.
	poolRaw, err := json.Marshal(settings.PoolSpec)
	if err != nil {
		return cfg.ErrInvalid
	}
	policy := *settings.PolicySpec
	if policy.PoolRef != settings.Pool || policy.Scope.ClusterID != "" && policy.Scope.ClusterID != cluster {
		return cfg.ErrInvalid
	}
	policy.Scope.ClusterID = cluster
	keys := map[string]bool{}
	for _, key := range settings.NamespaceKeys {
		keys[key] = true
	}
	for key := range policy.Scope.NamespaceSelector.MatchLabels {
		if !keys[key] {
			return cfg.ErrInvalid
		}
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		return cfg.ErrInvalid
	}
	validator, err := newCapacityValidator()
	if err != nil {
		return err
	}
	p := validator.poolObservation(permissionObject{Spec: poolRaw}, cfg.Resource{Name: settings.Pool})
	b := validator.policyObservation(permissionObject{Spec: policyRaw}, cfg.Resource{Name: settings.Policy})
	if p.Budget == nil || b.Budget == nil {
		return cfg.ErrInvalid
	}
	if _, err = capacityapp.CompileProtectedPool(*p.Budget, []capacityapp.PolicyBudgetInput{*b.Budget}); err != nil {
		return cfg.ErrInvalid
	}
	backend := false
	for _, item := range settings.Backends {
		if item.StorageProfile == p.StorageProfile && item.Usable.Bytes >= settings.PoolSpec.Capacity.Bytes && item.Usable.Objects >= settings.PoolSpec.Capacity.Objects {
			backend = true
		}
	}
	if !backend {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	currentNamespace := func() error {
		raw, e := api.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/" + control.Name).MaxRetries(0).DoRaw(call)
		var ns core.Namespace
		if e != nil || json.Unmarshal(raw, &ns) != nil {
			return cfg.ErrUnavailable
		}
		if string(ns.UID) != control.UID || ns.DeletionTimestamp != nil {
			return cfg.ErrChanged
		}
		return nil
	}
	if err = currentNamespace(); err != nil {
		return err
	}
	markers := map[string]string{"asservat.io/installation-id": installation, "asservat.io/control-namespace-uid": control.UID, "asservat.io/cluster-id": cluster}
	type object struct {
		meta.TypeMeta `json:",inline"`
		Metadata      meta.ObjectMeta `json:"metadata"`
		Spec          json.RawMessage `json:"spec"`
	}
	for _, source := range []struct {
		kind, plural, name string
		spec               []byte
	}{
		{"EvidenceStoragePool", "evidencestoragepools", settings.Pool, poolRaw},
		{"EvidenceBudgetPolicy", "evidencebudgetpolicies", settings.Policy, policyRaw},
	} {
		path := "/apis/asservat.io/v1alpha1/namespaces/" + control.Name + "/" + source.plural
		raw, e := api.CoreV1().RESTClient().Get().AbsPath(path + "/" + source.name).MaxRetries(0).DoRaw(call)
		if apierrors.IsNotFound(e) {
			proposed := object{TypeMeta: meta.TypeMeta{APIVersion: "asservat.io/v1alpha1", Kind: source.kind}, Metadata: meta.ObjectMeta{Name: source.name, Namespace: control.Name, Annotations: markers}, Spec: source.spec}
			// Unknown create replies stop this call; a later invocation may only
			// reopen this same original, exact marked desired object.
			body, marshalErr := json.Marshal(proposed)
			if marshalErr != nil {
				return cfg.ErrInvalid
			}
			raw, e = api.CoreV1().RESTClient().Post().AbsPath(path).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(call)
		}
		if e != nil {
			return cfg.ErrUnavailable
		}
		var got object
		var actual, want any
		if json.Unmarshal(raw, &got) != nil || exactCapacitySpec(got.Spec, &actual) != nil || exactCapacitySpec(source.spec, &want) != nil || !reflect.DeepEqual(actual, want) ||
			got.APIVersion != "asservat.io/v1alpha1" || got.Kind != source.kind || got.Metadata.Name != source.name || got.Metadata.Namespace != control.Name ||
			!authorization.UUID(string(got.Metadata.UID)) || got.Metadata.ResourceVersion == "" || got.Metadata.Generation < 1 || got.Metadata.DeletionTimestamp != nil ||
			len(got.Metadata.OwnerReferences) != 0 || len(got.Metadata.Finalizers) != 0 || len(got.Metadata.Labels) != 0 || !reflect.DeepEqual(got.Metadata.Annotations, markers) {
			return cfg.ErrChanged
		}
	}
	if err = currentNamespace(); err != nil {
		return err
	}
	return call.Err()
}

// Integer quantities must compare exactly even above binary64's safe range.
func exactCapacitySpec(raw []byte, out *any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(out)
}
