package kubernetes

import (
	"sync/atomic"
)

type ownerProjectionOperationFixture struct {
	*ownerIdentityOperationFixture
	provider      *ownerOperationProviderFixture
	roles         *ownerIdentityOperationSQLFixture
	verification  *ownerProjectionSQLFixture
	projection    *ProviderOwnerProjection
	creates       [2]atomic.Int32
	launches      atomic.Int32
	journalWrites atomic.Int32
	// Exact selected response failures only. The effect is either committed
	// then its response lost, or the original journal PUT never takes effect.
	lose        atomic.Int32 // 1 credentials CREATE, 2 configuration CREATE, 3 launch PUT, 4 journal PUT.
	dropJournal atomic.Bool
}

// The SQL portion is an explicit stand-in. All original native phases,
// concrete SetupReader HTTPS and original journal/object effects still run.
type ownerProjectionSQLFixture struct {
	roles                 *ownerIdentityOperationSQLFixture
	beforeCurrent         func()
	beforeEffect          func()
	beforeFinal           func()
	checks                int
	finalizations         int
	semanticVersion       int64
	beforeFinalizeCurrent func()
}

func (s *ownerProjectionSQLFixture) version() int64 {
	if s.semanticVersion == 0 {
		return 1
	}
	return s.semanticVersion
}
