package postgres

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Implemented by the native protected installer Secret, never runtime ingress.
// Only the positive boolean from its first CAS can start SQL creation.
type OwnerIdentityRoleRoot interface {
	OpenOwnerIdentityRoles(context.Context) (contracts.OwnerIdentityRoleSnapshot, error)
	ReadOwnerIdentityRoles(context.Context) (contracts.OwnerIdentityRoleSnapshot, error)
	ClaimOwnerIdentityRole(context.Context, string, uint32, time.Time) (contracts.OwnerIdentityRoleSnapshot, bool, error)
	CompleteOwnerIdentityRole(context.Context, contracts.OwnerIdentityRoleSnapshot, string, contracts.PublicRuntimeRoleReceipt) error
}

type OwnerIdentitySQLRoles struct {
	pool          *pgxpool.Pool
	root          OwnerIdentityRoleRoot
	input         contracts.OwnerIdentityRoles
	administrator uint32
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed, busy  bool
	work          sync.WaitGroup
}
