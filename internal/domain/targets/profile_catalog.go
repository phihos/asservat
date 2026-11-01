package targets

import (
	"encoding/json"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// MaxCatalogVersions bounds one namespace catalog read: a composition has at
// most eight components (REQ-CPR-003).
const MaxCatalogVersions = 8

// ProfileVersion names one exact CaptureProfile version; there is no latest.
type ProfileVersion struct{ Name, Version string }

// ProfileCatalogRequest asks the target's region for exact CaptureProfile
// versions in the target's own namespace (REQ-CPR-001). The namespace UID is
// the already resolved target's; the region refuses a replacement namespace.
type ProfileCatalogRequest struct {
	ClusterID string
	Namespace configuration.NamespaceRef
	Versions  []ProfileVersion
}

func (r ProfileCatalogRequest) Valid() bool {
	if !authorization.UUID(r.ClusterID) || !identity.Text(r.Namespace.Name, 63) || !identity.Text(r.Namespace.UID, 64) || len(r.Versions) < 1 || len(r.Versions) > MaxCatalogVersions {
		return false
	}
	for _, v := range r.Versions {
		if !identity.Text(v.Name, 63) || !identity.Text(v.Version, 32) {
			return false
		}
	}
	return true
}

// CaptureProfileObject is one published version as read. Missing versions are
// absent; the hub's compiler names them. Definition is untrusted until the
// compiler's strict decode.
type CaptureProfileObject struct {
	Name, Version, UID  string
	Definition          json.RawMessage
	Enabled, Deprecated bool
}

// ProfileCatalogAnswer echoes the exact request scope it answers.
type ProfileCatalogAnswer struct {
	ClusterID string
	Namespace configuration.NamespaceRef
	Profiles  []CaptureProfileObject
}

// Answers reports whether a is a bounded answer to exactly r.
func (a ProfileCatalogAnswer) Answers(r ProfileCatalogRequest) bool {
	if a.ClusterID != r.ClusterID || a.Namespace != r.Namespace || len(a.Profiles) > len(r.Versions) {
		return false
	}
	asked := map[ProfileVersion]bool{}
	for _, v := range r.Versions {
		asked[v] = true
	}
	for _, p := range a.Profiles {
		v := ProfileVersion{p.Name, p.Version}
		if !asked[v] || !identity.Text(p.UID, 64) || len(p.Definition) == 0 {
			return false
		}
		delete(asked, v)
	}
	return true
}
