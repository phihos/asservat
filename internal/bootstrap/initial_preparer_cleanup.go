package bootstrap

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These lazy consumers are used only for unfinished cleanup. A completed
// passive replay does not load expired preparation or provider credentials.
func (d *InitialPreparationDeployment) RetireInitialSQL(ctx context.Context, v contracts.InitialSQLCredentialState) error {
	if d == nil || d.preparer == nil || !d.preparer.HandoverEnabled() || v.InstallationID != d.configuration.Plan.InstallationID {
		return mounts.ErrUnavailable
	}
	if d.sqlRoles == nil {
		d.inputs.postgresEndpoint = d.configuration.Services.Postgres
		config, e := d.inputs.sqlConfig(ctx, "sql-maintenance.json")
		if e != nil {
			return e
		}
		pool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			return mounts.ErrUnavailable
		}
		roles, e := postgres.NewInitialSQLRoles(ctx, pool, v.InstallationID)
		if e != nil {
			pool.Close()
			return e
		}
		d.sqlPool = pool
		d.sqlRoles = roles
	}
	p := postgres.InitialSQLCredentials{InstallationID: v.InstallationID, NotBefore: v.NotBefore, NotAfter: v.NotAfter, Preparation: postgres.InitialSQLLogin{Username: v.Preparation.Username, Password: v.Preparation.Password}, Audit: postgres.InitialSQLLogin{Username: v.Audit.Username, Password: v.Audit.Password}, Activation: postgres.InitialSQLLogin{Username: v.Activation.Username, Password: v.Activation.Password}}
	return d.sqlRoles.Retire(ctx, p)
}
func (d *InitialPreparationDeployment) RetireInitialProvider(ctx context.Context, purpose string, parent contracts.InitialProviderParent, issue contracts.InitialProviderIssue, response contracts.InitialProviderResponse) error {
	if d == nil || d.preparer == nil || !d.preparer.HandoverEnabled() {
		return mounts.ErrUnavailable
	}
	if d.providerIssuer == nil {
		material, until, e := d.preparer.ReadHandoverProviderMaterial(ctx)
		if e != nil {
			return e
		}
		var end context.CancelFunc
		ctx, end = context.WithDeadline(ctx, until)
		defer end()
		c := d.configuration
		h, e := ownerHTTP(c.Services.KeyService.Endpoint, c.Services.KeyService.Roots)
		if e != nil {
			return e
		}
		defer h.CloseIdleConnections()
		d.providerIssuer, e = kms.NewInitialProviderIssuer(c.Services.KeyService.Endpoint, material.IssuerToken, c.Services.KeyService.AuditMount, c.Services.KeyService.AuditKey, c.Plan.InstallationID, c.Plan.RequestID, *c.Providers, h, time.Now)
		if e != nil {
			return e
		}
	}
	until, e := d.providerIssuer.Revoke(ctx, purpose, issue, parent, response)
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return mounts.ErrUnavailable
	}
	return nil
}
