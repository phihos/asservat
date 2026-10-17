package kubernetes

import (
	"context"
	"reflect"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enumerate every ConfigMap/Secret reference in the closed profile. Explicit
// Pod-token projections are dynamic; their specification remains template-pinned
// and the connector token receives its separate current TokenReview. There is
// no generic volume plugin, opaque injection or inherited env source fallback.
func connectorAPIInputNames(p core.PodSpec) (map[string]bool, error) {
	refs := map[string]bool{}
	add := func(kind, name string) bool {
		if name == "" {
			return false
		}
		refs[kind+"/"+name] = true
		return len(refs) <= 16
	}
	for _, pull := range p.ImagePullSecrets {
		if !add("Secret", pull.Name) {
			return nil, cfg.ErrInvalid
		}
	}
	for _, v := range p.Volumes {
		rest := *v.VolumeSource.DeepCopy()
		count := 0
		if v.Secret != nil {
			count++
			if !add("Secret", v.Secret.SecretName) {
				return nil, cfg.ErrInvalid
			}
			rest.Secret = nil
		}
		if v.ConfigMap != nil {
			count++
			if !add("ConfigMap", v.ConfigMap.Name) {
				return nil, cfg.ErrInvalid
			}
			rest.ConfigMap = nil
		}
		if v.EmptyDir != nil {
			count++
			if v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.Sign() <= 0 {
				return nil, cfg.ErrInvalid
			}
			rest.EmptyDir = nil
		}
		if v.Projected != nil {
			count++
			rest.Projected = nil
			for _, source := range v.Projected.Sources {
				r := *source.DeepCopy()
				n := 0
				if source.Secret != nil {
					n++
					if !add("Secret", source.Secret.Name) {
						return nil, cfg.ErrInvalid
					}
					r.Secret = nil
				}
				if source.ConfigMap != nil {
					n++
					if !add("ConfigMap", source.ConfigMap.Name) {
						return nil, cfg.ErrInvalid
					}
					r.ConfigMap = nil
				}
				if source.DownwardAPI != nil {
					n++
					r.DownwardAPI = nil
				}
				if source.ServiceAccountToken != nil {
					n++
					if source.ServiceAccountToken.ExpirationSeconds == nil || *source.ServiceAccountToken.ExpirationSeconds < 600 || *source.ServiceAccountToken.ExpirationSeconds > 3600 {
						return nil, cfg.ErrInvalid
					}
					r.ServiceAccountToken = nil
				}
				if n != 1 || !reflect.DeepEqual(r, core.VolumeProjection{}) {
					return nil, cfg.ErrInvalid
				}
			}
		}
		if count != 1 || !reflect.DeepEqual(rest, core.VolumeSource{}) {
			return nil, cfg.ErrInvalid
		}
	}
	for _, c := range p.Containers {
		for _, from := range c.EnvFrom {
			n := 0
			if from.ConfigMapRef != nil {
				n++
				if !add("ConfigMap", from.ConfigMapRef.Name) {
					return nil, cfg.ErrInvalid
				}
			}
			if from.SecretRef != nil {
				n++
				if !add("Secret", from.SecretRef.Name) {
					return nil, cfg.ErrInvalid
				}
			}
			if n != 1 {
				return nil, cfg.ErrInvalid
			}
		}
		for _, env := range c.Env {
			if env.ValueFrom == nil {
				continue
			}
			v := env.ValueFrom
			n := 0
			if v.ConfigMapKeyRef != nil {
				n++
				if !add("ConfigMap", v.ConfigMapKeyRef.Name) {
					return nil, cfg.ErrInvalid
				}
			}
			if v.SecretKeyRef != nil {
				// The separately accepted dedicated-object pin authorizes GET of
				// the entire role-owned object, independently of mount syntax.
				n++
				if !add("Secret", v.SecretKeyRef.Name) {
					return nil, cfg.ErrInvalid
				}
			}
			if v.FieldRef != nil {
				n++
			}
			if v.ResourceFieldRef != nil {
				n++
			}
			if n != 1 {
				return nil, cfg.ErrInvalid
			}
		}
	}
	return refs, nil
}

func (g *ConnectorAPIExecutionProtection) inputs(ctx context.Context, p core.PodSpec) error {
	refs, e := connectorAPIInputNames(p)
	if e != nil {
		return e
	}
	// The source cannot encode its own UID/RV before creation. Its independent
	// constructor pins plus current exact immutable source read cover this key.
	delete(refs, "ConfigMap/"+g.name)
	if len(refs) != len(g.installed.Inputs) {
		return cfg.ErrChanged
	}
	for _, in := range g.installed.Inputs {
		if !refs[in.Kind+"/"+in.Name] {
			return cfg.ErrChanged
		}
	}
	for _, in := range g.installed.Inputs {
		if e = g.inputMetadata(ctx, in); e != nil {
			return e
		}
	}
	return nil
}
func (g *ConnectorAPIExecutionProtection) inputMetadata(ctx context.Context, in contracts.ConnectorAPIInput) error {
	// This Accept limits returned bytes, not RBAC. The installed profile must
	// dedicate each complete Secret to this role, with exact named get grants.
	resource := "configmaps"
	if in.Kind == "Secret" {
		resource = "secrets"
	} else if in.Kind != "ConfigMap" {
		return cfg.ErrInvalid
	}
	raw, e := g.attester.client.api.Get().AbsPath("/api/v1/namespaces/"+g.installed.Namespace+"/"+resource+"/"+in.Name).SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1").MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var m meta.PartialObjectMetadata
	if e != nil || permissionJSON(raw, 16<<10, 4096) != nil || strictGuardJSON(raw, &m) != nil || m.APIVersion != "meta.k8s.io/v1" || m.Kind != "PartialObjectMetadata" || !ownerMetadata(m.ObjectMeta, g.installed.Namespace, in.Name, in.UID) || m.ResourceVersion != in.ResourceVersion {
		return cfg.ErrChanged
	}
	return nil
}
