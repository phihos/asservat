package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	app "asservat.local/asservat/internal/application/capture"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// CaptureProfileCatalog reads published CaptureProfile versions
// (REQ-CPR-001) with one bounded GET per referenced version.
// Organization versions come from the hub's protected catalog namespace.
// Namespace versions live in the workload clusters and are not read by this
// hub-local reader yet, so they resolve as unpublished.
type CaptureProfileCatalog struct {
	client    *PermissionClient
	namespace value.NamespaceRef
}

var _ app.CatalogProfiles = (*CaptureProfileCatalog)(nil)

// NewCaptureProfileCatalog reads organization profiles from namespace (the
// installation's protected hub namespace) through client.
func NewCaptureProfileCatalog(client *PermissionClient, namespace value.NamespaceRef) (*CaptureProfileCatalog, error) {
	if client == nil || !namespaceRefValid(namespace) {
		return nil, value.ErrInvalid
	}
	return &CaptureProfileCatalog{client: client, namespace: namespace}, nil
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

func (c *CaptureProfileCatalog) ReadCatalogProfiles(ctx context.Context, _ targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	var out []planning.CatalogProfile
	seen := map[planning.ProfileRef]bool{}
	for _, ref := range refs {
		if ref.Catalog != "organization" || seen[ref] || !ref.Valid() {
			continue
		}
		seen[ref] = true
		name := ref.Name + "." + ref.Version
		b, err := c.client.raw(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+c.namespace.Name+"/captureprofiles/"+name, nil)
		if errors.Is(err, value.ErrChanged) {
			continue // not published; the compiler names the missing version
		}
		if err != nil {
			return nil, err
		}
		var o captureProfileObject
		if json.Unmarshal(b, &o) != nil || o.Metadata.Name != name || o.Metadata.Namespace != c.namespace.Name || o.Metadata.UID == "" || len(o.Metadata.UID) > 64 ||
			o.Spec.Name != ref.Name || o.Spec.Version != ref.Version || len(bytes.TrimSpace(o.Spec.Definition)) == 0 {
			return nil, value.ErrInvalid
		}
		// The compiler strictly decodes and digests exactly this document.
		document, err := json.Marshal(struct {
			Name       string          `json:"name"`
			Version    string          `json:"version"`
			Definition json.RawMessage `json:"definition"`
		}{o.Spec.Name, o.Spec.Version, o.Spec.Definition})
		if err != nil {
			return nil, value.ErrInvalid
		}
		out = append(out, planning.CatalogProfile{Ref: ref, SourceClusterID: c.client.clusterID, SourceNamespaceUID: c.namespace.UID, SourceUID: o.Metadata.UID,
			Document: document, Enabled: o.Spec.Availability.Enabled, Deprecated: o.Spec.Availability.Deprecated})
	}
	return out, nil
}
