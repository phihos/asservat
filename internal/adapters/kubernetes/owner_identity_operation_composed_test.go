package kubernetes

import (
	"context"
	"time"
)

// This test-only SQL stand-in never claims PostgreSQL qualification. It drives
// the actual concrete native phase methods/CAS against the loopback API and
// counts irreversible role effects separately from original claim receipts.
type ownerIdentityOperationSQLFixture struct {
	root          *OwnerIdentityRoleRoot
	beforeCurrent func()
	beforeFinal   func()
	effects       map[string]string
	creates       int
	loseEffect    bool
}

func (s *ownerIdentityOperationSQLFixture) ReadOwnerIdentityRoleIncarnation(context.Context) (uint32, time.Time, error) {
	return 42, time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond), nil
}
