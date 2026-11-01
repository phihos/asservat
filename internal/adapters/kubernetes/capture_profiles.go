package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/util/validation"
)

// CaptureProfileCatalog reads published CaptureProfile versions
// (REQ-CPR-001) with one bounded GET per referenced version. Organization
// versions come from the hub's protected catalog namespace; namespace
// versions are read by the target's region from the target's own namespace.
type CaptureProfileCatalog struct {
	client    *PermissionClient
	namespace value.NamespaceRef
	// Regions answers namespace catalog reads; nil leaves namespace versions
	// unpublished.
	Regions NamespaceProfiles
}

// NamespaceProfiles is the hub's regional query for namespace catalogs.
type NamespaceProfiles interface {
	ReadCaptureProfiles(context.Context, targets.ProfileCatalogRequest) (targets.ProfileCatalogAnswer, error)
	ListCaptureProfiles(context.Context, targets.ProfileListRequest) (targets.ProfileCatalogAnswer, error)
}

var _ app.CatalogProfiles = (*CaptureProfileCatalog)(nil)

// NewCaptureProfileCatalog reads organization profiles from namespace (the
// installation's protected hub namespace) through client.
func NewCaptureProfileCatalog(client *PermissionClient, namespace value.NamespaceRef, regions NamespaceProfiles) (*CaptureProfileCatalog, error) {
	if client == nil || !namespaceRefValid(namespace) {
		return nil, value.ErrInvalid
	}
	return &CaptureProfileCatalog{client: client, namespace: namespace, Regions: regions}, nil
}

type captureProfileObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Name         string          `json:"name"`
		Version      string          `json:"version"`
		Definition   json.RawMessage `json:"definition"`
		Availability struct {
			Enabled    bool `json:"enabled"`
			Deprecated bool `json:"deprecated"`
		} `json:"availability"`
	} `json:"spec"`
}

// decodeCaptureProfile strictly checks one object read from namespace.
func decodeCaptureProfile(raw captureProfileObject, namespace string) (targets.CaptureProfileObject, error) {
	v := targets.ProfileVersion{Name: raw.Spec.Name, Version: raw.Spec.Version}
	if raw.Metadata.Name != v.Name+"."+v.Version || raw.Metadata.Namespace != namespace || raw.Metadata.UID == "" || len(raw.Metadata.UID) > 64 ||
		len(v.Name) == 0 || len(v.Name) > 63 || len(v.Version) == 0 || len(v.Version) > 32 || len(bytes.TrimSpace(raw.Spec.Definition)) == 0 {
		return targets.CaptureProfileObject{}, value.ErrInvalid
	}
	return targets.CaptureProfileObject{Name: v.Name, Version: v.Version, UID: raw.Metadata.UID, Definition: raw.Spec.Definition,
		Enabled: raw.Spec.Availability.Enabled, Deprecated: raw.Spec.Availability.Deprecated}, nil
}

// listCaptureProfiles is one bounded LIST of namespace; more than
// MaxListedProfiles versions is ErrLimit, never a silent truncation.
func listCaptureProfiles(ctx context.Context, client *PermissionClient, namespace string) ([]targets.CaptureProfileObject, error) {
	b, err := client.raw(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+namespace+"/captureprofiles", map[string]string{"limit": strconv.Itoa(targets.MaxListedProfiles + 1)})
	if err != nil {
		return nil, err
	}
	var list struct {
		Metadata struct {
			Continue           string `json:"continue"`
			RemainingItemCount *int64 `json:"remainingItemCount"`
		} `json:"metadata"`
		Items []captureProfileObject `json:"items"`
	}
	if json.Unmarshal(b, &list) != nil {
		return nil, value.ErrInvalid
	}
	if list.Metadata.Continue != "" || len(list.Items) > targets.MaxListedProfiles || list.Metadata.RemainingItemCount != nil && *list.Metadata.RemainingItemCount != 0 {
		return nil, targets.ErrLimit
	}
	out := []targets.CaptureProfileObject{}
	for _, item := range list.Items {
		o, err := decodeCaptureProfile(item, namespace)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// readCaptureProfile GETs one exact version; ok is false when it is not
// published.
func readCaptureProfile(ctx context.Context, client *PermissionClient, namespace string, v targets.ProfileVersion) (o targets.CaptureProfileObject, ok bool, err error) {
	name := v.Name + "." + v.Version
	b, err := client.raw(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+namespace+"/captureprofiles/"+name, nil)
	if errors.Is(err, value.ErrChanged) {
		return o, false, nil // not published; the compiler names the missing version
	}
	if err != nil {
		return o, false, err
	}
	var raw captureProfileObject
	if json.Unmarshal(b, &raw) != nil || raw.Spec.Name != v.Name || raw.Spec.Version != v.Version {
		return o, false, value.ErrInvalid
	}
	o, err = decodeCaptureProfile(raw, namespace)
	return o, err == nil, err
}

// catalogProfile is the compiler's view of one read object.
func catalogProfile(ref planning.ProfileRef, cluster, namespaceUID string, o targets.CaptureProfileObject) (planning.CatalogProfile, error) {
	// The compiler strictly decodes and digests exactly this document.
	document, err := json.Marshal(struct {
		Name       string          `json:"name"`
		Version    string          `json:"version"`
		Definition json.RawMessage `json:"definition"`
	}{o.Name, o.Version, json.RawMessage(o.Definition)})
	if err != nil {
		return planning.CatalogProfile{}, value.ErrInvalid
	}
	return planning.CatalogProfile{Ref: ref, SourceClusterID: cluster, SourceNamespaceUID: namespaceUID, SourceUID: o.UID,
		Document: document, Enabled: o.Enabled, Deprecated: o.Deprecated}, nil
}

// ListCatalogProfiles lists the organization catalog (one hub LIST) and the
// target namespace's catalog (one regional LIST), or only catalog's.
func (c *CaptureProfileCatalog) ListCatalogProfiles(ctx context.Context, target targets.PodResolution, catalog string) ([]planning.CatalogProfile, error) {
	var out []planning.CatalogProfile
	add := func(name, cluster, namespaceUID string, objects []targets.CaptureProfileObject) error {
		for _, o := range objects {
			p, err := catalogProfile(planning.ProfileRef{Catalog: name, Name: o.Name, Version: o.Version}, cluster, namespaceUID, o)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return nil
	}
	if catalog == "" || catalog == "organization" {
		objects, err := listCaptureProfiles(ctx, c.client, c.namespace.Name)
		if err != nil {
			return nil, err
		}
		if err = add("organization", c.client.clusterID, c.namespace.UID, objects); err != nil {
			return nil, err
		}
	}
	if (catalog == "" || catalog == "namespace") && c.Regions != nil {
		r := targets.ProfileListRequest{ClusterID: target.Request.ClusterID, Namespace: target.Request.Namespace}
		if !r.Valid() {
			return nil, value.ErrInvalid
		}
		answer, err := c.Regions.ListCaptureProfiles(ctx, r)
		if err != nil {
			return nil, err
		}
		if !answer.Lists(r) {
			return nil, value.ErrInvalid
		}
		if err = add("namespace", r.ClusterID, r.Namespace.UID, answer.Profiles); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *CaptureProfileCatalog) ReadCatalogProfiles(ctx context.Context, target targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	var out []planning.CatalogProfile
	seen := map[planning.ProfileRef]bool{}
	local := targets.ProfileCatalogRequest{ClusterID: target.Request.ClusterID, Namespace: target.Request.Namespace}
	add := func(ref planning.ProfileRef, cluster, namespaceUID string, o targets.CaptureProfileObject) error {
		p, err := catalogProfile(ref, cluster, namespaceUID, o)
		out = append(out, p)
		return err
	}
	for _, ref := range refs {
		if ref.Catalog == "builtin" || seen[ref] || !ref.Valid() {
			continue
		}
		seen[ref] = true
		v := targets.ProfileVersion{Name: ref.Name, Version: ref.Version}
		if ref.Catalog == "namespace" {
			local.Versions = append(local.Versions, v)
			continue
		}
		o, ok, err := readCaptureProfile(ctx, c.client, c.namespace.Name, v)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := add(ref, c.client.clusterID, c.namespace.UID, o); err != nil {
				return nil, err
			}
		}
	}
	if len(local.Versions) == 0 || c.Regions == nil {
		return out, nil
	}
	if !local.Valid() {
		return nil, value.ErrInvalid
	}
	answer, err := c.Regions.ReadCaptureProfiles(ctx, local)
	if err != nil {
		return nil, err
	}
	if !answer.Answers(local) {
		return nil, value.ErrInvalid
	}
	for _, o := range answer.Profiles {
		ref := planning.ProfileRef{Catalog: "namespace", Name: o.Name, Version: o.Version}
		if err := add(ref, local.ClusterID, local.Namespace.UID, o); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ListCaptureProfiles is the region's namespace catalog listing: one
// namespace GET binding the target's namespace UID, then one bounded LIST
// (`list` on captureprofiles).
func (c *PodTargets) ListCaptureProfiles(ctx context.Context, r targets.ProfileListRequest) (targets.ProfileCatalogAnswer, error) {
	var zero targets.ProfileCatalogAnswer
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace.Name)) != 0 {
		return zero, targets.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := c.namedNamespace(ctx, r.Namespace.Name)
	if err != nil {
		return zero, err
	}
	if ns != r.Namespace {
		return zero, targets.ErrChanged
	}
	objects, err := listCaptureProfiles(ctx, c.client, ns.Name)
	if errors.Is(err, targets.ErrLimit) {
		return zero, err
	}
	if err != nil {
		return zero, targetReadError(err)
	}
	return targets.ProfileCatalogAnswer{ClusterID: r.ClusterID, Namespace: ns, Profiles: objects}, nil
}

// ReadCaptureProfiles is the region's namespace catalog read: one namespace
// GET binding the target's namespace UID, then one GET per version in that
// namespace only (`get` on captureprofiles).
func (c *PodTargets) ReadCaptureProfiles(ctx context.Context, r targets.ProfileCatalogRequest) (targets.ProfileCatalogAnswer, error) {
	var zero targets.ProfileCatalogAnswer
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace.Name)) != 0 {
		return zero, targets.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := c.namedNamespace(ctx, r.Namespace.Name)
	if err != nil {
		return zero, err
	}
	if ns != r.Namespace {
		return zero, targets.ErrChanged
	}
	out := targets.ProfileCatalogAnswer{ClusterID: r.ClusterID, Namespace: ns, Profiles: []targets.CaptureProfileObject{}}
	seen := map[targets.ProfileVersion]bool{}
	for _, v := range r.Versions {
		if seen[v] {
			continue
		}
		seen[v] = true
		o, ok, err := readCaptureProfile(ctx, c.client, ns.Name, v)
		if err != nil {
			return zero, targetReadError(err)
		}
		if ok {
			out.Profiles = append(out.Profiles, o)
		}
	}
	return out, nil
}
