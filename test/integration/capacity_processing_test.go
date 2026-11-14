package integration

import (
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/audit"
)

func (f *capacitySQLFixture) readAuditProfiles(t *testing.T) audit.AcceptedCapacityAuditProfiles {
	t.Helper()
	r, err := postgres.NewCapacityAuditProfiles(f.ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest, f.input.AccountVersion)
	if err != nil {
		t.Fatal("scoped profile constructor", err)
	}
	value, err := r.ReadCapacityAuditProfiles(f.ctx)
	if err != nil {
		t.Fatal("current exact scoped profiles", err)
	}
	return value
}
