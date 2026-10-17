package bootstrap

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

// prepareSQL composes the original private material and current native guards
// with the existing scoped SQL provisioner and optional bounded provider phase.
// It does not change the activation witness, staging protection or Pod gate.
func (d *InitialPreparationDeployment) prepareSQL(ctx context.Context) (err error) {
	phase := "sql-inputs"
	defer func() {
		if err != nil {
			err = initialPreparerRunFailure{phase, err}
		}
	}()
	if d == nil || d.sqlMaterial == nil || d.sqlRoles == nil {
		return mounts.ErrUnavailable
	}
	phase = "read-prepared-inputs"
	observed, e := d.preparer.ReadPreparedInputs(ctx)
	if e != nil {
		return e
	}
	phase = "prepare-probe"
	probe, e := d.preparer.PrepareProbe(ctx)
	if e != nil {
		return e
	}
	defer clear(probe.Token)
	// The configuration is immutable public provenance; Bind independently reads
	// and checks its exact original UID/guard/Pod before issuing any fresh lease.
	c := observed.Configuration
	ctx, end := context.WithDeadline(ctx, probe.ExpiresAt)
	defer end()
	ns := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	adminConfig := d.inputs.kubernetes("administrator-token")
	phase = "sql-administrator-client"
	admin, e := kube.NewPermissionClient(adminConfig, c.ClusterID, ns, time.Now)
	if e != nil {
		return e
	}
	// Do not copy the administrator bearer wrapper into the target probe client.
	// The only credential here is the exact original authenticated token.
	probeConfig := &rest.Config{Host: adminConfig.Host, TLSClientConfig: adminConfig.TLSClientConfig, BearerToken: string(probe.Token), WrapTransport: func(t http.RoundTripper) http.RoundTripper {
		d.inputs.mu.Lock()
		d.inputs.transports = append(d.inputs.transports, t)
		d.inputs.mu.Unlock()
		return t
	}}
	phase = "sql-probe-client"
	targetProbe, e := kube.NewPermissionClient(probeConfig, c.ClusterID, ns, time.Now)
	if e != nil {
		return e
	}
	phase = "sql-binder"
	binder, e := kube.NewInitialPreparationCredentialBinder(d.preparer, admin, targetProbe, c, observed.Input.UID, *d.sqlMaterial)
	if e != nil {
		return e
	}
	phase = "sql-bind"
	material, binding, _, e := binder.Bind(ctx)
	if e != nil {
		return e
	}
	phase = "sql-credential-bind"
	credentials, e := postgres.BindInitialSQLMaterial(material, c.InstallationID, material.RequestID, binding.NotBefore, binding.NotAfter)
	if e != nil {
		return e
	}
	phase = "sql-startup-digest"
	raw, e := hex.DecodeString(binding.StartupDigest)
	if e != nil || len(raw) != 32 {
		return mounts.ErrUnavailable
	}
	var digest artifact.Digest
	copy(digest[:], raw)
	phase = "sql-credential-encoding"
	payload, e := postgres.EncodeInitialSQLCredentials(credentials, digest)
	if e != nil {
		return e
	}
	defer clear(payload)
	phase = "sql-state-persist"
	stored, e := binder.PersistSQLState(ctx, payload)
	if e != nil {
		return e
	}
	// Keep the original independent Kubernetes lease through SQL locks/COMMIT and
	// the fresh credential authentication checks. A lost/late reply stays uncertain.
	effect, done := context.WithDeadline(ctx, stored.ValidUntil)
	defer done()
	phase = "sql-provision"
	if e = d.sqlRoles.Provision(effect, credentials); e != nil {
		return e
	}
	phase = "sql-final-binding"
	if _, _, _, e = binder.Bind(effect); e != nil {
		return e
	}
	phase = "sql-final-deadline"
	if effect.Err() != nil || !time.Now().Before(stored.ValidUntil) {
		return mounts.ErrUnavailable
	}
	if d.preparer.HandoverEnabled() {
		phase = "history-current-binding"
		_, _, historyUntil, e := binder.Bind(ctx)
		if e != nil {
			return e
		}
		historyEffect, stop := context.WithDeadline(ctx, historyUntil)
		phase = "history-role-provision"
		e = d.sqlRoles.ProvisionHistory(historyEffect, credentials, d.historyLogin, *d.configuration.Plan.HistoryManager)
		if e == nil {
			phase = "history-final-binding"
			_, _, _, e = binder.Bind(historyEffect)
		}
		if e == nil {
			phase = "history-final-deadline"
		}
		if e == nil && (historyEffect.Err() != nil || !time.Now().Before(historyUntil)) {
			e = mounts.ErrUnavailable
		}
		stop()
		if e != nil {
			return e
		}
	}
	if d.providerIssuer != nil {
		for _, purpose := range []string{"wrap", "unwrap"} {
			phase = "provider-wrap"
			if purpose == "unwrap" {
				phase = "provider-unwrap"
			}
			if _, _, e = binder.PrepareProvider(ctx, purpose, d.providerIssuer); e != nil {
				return e
			}
		}
		phase = "provider-projection"
		if _, e = binder.PersistProviderProjection(ctx, d.providerIssuer); e != nil {
			return e
		}
	}
	return nil
}
