package privacy

import "asservat.local/asservat/internal/domain/identity"

// ProcessingOrganization is an operator declaration for inventory reporting.
// These fields do not grant access or select a processing path.
type ProcessingOrganization struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Activities []string `json:"activities"`
	Regions    []string `json:"regions"`
}

func ProcessingOrganizationsValid(organizations []ProcessingOrganization) bool {
	if len(organizations) > 16 {
		return false
	}
	seen := make(map[string]bool, len(organizations))
	for _, organization := range organizations {
		if !identity.Text(organization.ID, 64) || !identity.Text(organization.Name, 160) || seen[organization.ID] ||
			len(organization.Activities) == 0 || !identity.Strings(organization.Activities, 8, 128) ||
			organization.Regions == nil || !identity.Strings(organization.Regions, 16, 128) {
			return false
		}
		seen[organization.ID] = true
	}
	return true
}
