package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

type configurationRoleInstallerError string

func (e configurationRoleInstallerError) Error() string {
	return "configuration-role-install: " + string(e)
}
func (e configurationRoleInstallerError) Is(target error) bool {
	return target == mounts.ErrUnavailable
}

const (
	configurationRoleInputInvalid          configurationRoleInstallerError = "InputInvalid"
	configurationRoleProtectionUnavailable configurationRoleInstallerError = "ProtectionUnavailable"
	configurationRoleSQLUnavailable        configurationRoleInstallerError = "SQLRoleProvisioningUnavailable"
	configurationRoleProjectionUnavailable configurationRoleInstallerError = "RuntimeProjectionUnavailable"
	configurationRoleLaunchUnavailable     configurationRoleInstallerError = "RuntimeLaunchUnavailable"
)

func configurationRoleInstallerPlan(c contracts.ConfigurationRoleInstaller) (cfg.OwnerWorkloadAdministration, kube.GuardPin, error) {
	var zero cfg.OwnerWorkloadAdministration
	if c.Format != contracts.ConfigurationRoleInstallerFormat || c.Roles.Format != contracts.ConfigurationRuntimeRolesFormat || c.Roles.LayoutDigest != postgres.ConfigurationRuntimeRoleLayoutDigest() || !authorization.UUID(c.Roles.InstallationID) || !authorization.UUID(c.Roles.InitialClaimID) || !authorization.UUID(c.Roles.ClusterID) || !authorization.UUID(c.Roles.Namespace.UID) || len(validation.IsDNS1123Label(c.Roles.Namespace.Name)) != 0 || c.ConfigurationProbes == nil || len(c.ConfigurationProbes) > cfg.MaxOwnerConfigurationProbes || c.SchedulingLeases == nil || len(c.SchedulingLeases) > 4 {
		return zero, kube.GuardPin{}, configurationRoleInputInvalid
	}
	if l := c.Launch; l != nil {
		for _, r := range []contracts.WorkerObjectReference{l.Configuration, l.Providers} {
			if !authorization.UUID(r.UID) || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
				return zero, kube.GuardPin{}, configurationRoleInputInvalid
			}
		}
		if l.Configuration.Name == c.Roles.FleetSource.Name || l.Configuration.Name == c.Roles.OwnerSource.Name || l.Configuration.UID == l.Providers.UID {
			return zero, kube.GuardPin{}, configurationRoleInputInvalid
		}
	}
	for _, r := range []contracts.WorkerObjectReference{c.OwnerDeployment, c.Roles.Deployment, c.Roles.ServiceAccount, c.Roles.FleetSource, c.Roles.OwnerSource} {
		if !authorization.UUID(r.UID) || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
			return zero, kube.GuardPin{}, configurationRoleInputInvalid
		}
	}
	if c.Roles.FleetSource.UID == c.Roles.OwnerSource.UID || c.Roles.FleetSource.Name == c.Roles.OwnerSource.Name || c.FleetGuard.Name == c.OwnerGuard.Name || c.WorkloadGuard.Name == c.FleetGuard.Name || c.WorkloadGuard.Name == c.OwnerGuard.Name || !ownerEndpoint(c.Kubernetes.Endpoint) || c.Postgres.MaxConnections != 1 || !identity.Text(c.Postgres.Database, 63) || c.Postgres.Port < 1 || c.Postgres.Port > 65535 {
		return zero, kube.GuardPin{}, configurationRoleInputInvalid
	}
	if _, e := netip.ParseAddr(c.Postgres.Host); e != nil && !ownerDNSName.MatchString(c.Postgres.Host) {
		return zero, kube.GuardPin{}, configurationRoleInputInvalid
	}
	for _, roots := range [][][]byte{c.Kubernetes.Roots, c.Postgres.Roots} {
		if _, _, e := mtls.OwnerTrustRoots(roots, time.Now()); e != nil {
			return zero, kube.GuardPin{}, configurationRoleInputInvalid
		}
	}
	for _, g := range []contracts.OwnerDeploymentGuard{c.WorkloadGuard, c.FleetGuard, c.OwnerGuard} {
		if !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || g.PolicyGeneration < 1 || g.PolicyGeneration >= 1<<53 || !identity.Text(g.BindingResourceVersion, 128) || len(g.Administrators) < 1 || len(g.Administrators) > 32 {
			return zero, kube.GuardPin{}, configurationRoleInputInvalid
		}
	}
	g := c.WorkloadGuard
	plan := cfg.OwnerWorkloadAdministration{Name: g.Name, Deployment: c.OwnerDeployment.Name, DeploymentUID: c.OwnerDeployment.UID, ControlNamespace: cfg.NamespaceRef{Name: c.Roles.Namespace.Name, UID: c.Roles.Namespace.UID}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{}, SchedulingLeases: []cfg.OwnerSchedulingLease{}}
	capacityProbe, capacityErr := ownerDeploymentCapacityProbe(c.CapacityProbe)
	if capacityErr != nil {
		return zero, kube.GuardPin{}, configurationRoleInputInvalid
	}
	plan.CapacityProbe = capacityProbe
	if h := c.InitialHistoryProbe; h != nil {
		plan.InitialHistoryProbe = &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: h.Namespace.Name, UID: h.Namespace.UID}, ServiceAccount: h.ServiceAccount.Name, ServiceAccountUID: h.ServiceAccount.UID, Configuration: h.Configuration}
	}
	for _, a := range g.Administrators {
		plan.Administrators = append(plan.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	for _, p := range c.ConfigurationProbes {
		plan.ConfigurationProbes = append(plan.ConfigurationProbes, cfg.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount})
	}
	for _, l := range c.SchedulingLeases {
		plan.SchedulingLeases = append(plan.SchedulingLeases, cfg.OwnerSchedulingLease{Lease: l.Lease, ServiceAccount: l.ServiceAccount})
	}
	if !plan.Valid() {
		return zero, kube.GuardPin{}, configurationRoleInputInvalid
	}
	return plan, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}, nil
}
func provisionConfigurationRoles(ctx context.Context, files *os.Root) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if ctx == nil || ctx.Err() != nil || files == nil {
		return zero, configurationRoleInputInvalid
	}
	b, e := mounts.Read(ctx, files, "deployment.json", contracts.ConfigurationRoleInstallerMaxBytes)
	if e != nil {
		return zero, configurationRoleInputInvalid
	}
	c, e := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(b))
	clear(b)
	if e != nil {
		return zero, configurationRoleInputInvalid
	}
	plan, pin, e := configurationRoleInstallerPlan(c)
	if e != nil {
		return zero, e
	}
	in := &providerInputs{oneShot: true, files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}
	defer in.closeHTTP()
	admin, e := kube.NewPermissionClient(in.kubernetes("kube-administrator.token"), c.Roles.ClusterID, plan.ControlNamespace, time.Now)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	probe, e := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.Roles.ClusterID, plan.ControlNamespace, time.Now)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	protection, e := kube.NewOwnerWorkloadProtection(admin, probe, plan, pin)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	sourcePlan := func(g contracts.OwnerDeploymentGuard, name string) (cfg.ConfigMapAdministration, kube.GuardPin) {
		p := cfg.ConfigMapAdministration{Name: g.Name, SourceName: name, ControlNamespace: plan.ControlNamespace}
		for _, a := range g.Administrators {
			p.Administrators = append(p.Administrators, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
		}
		return p, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	fp, fg := sourcePlan(c.FleetGuard, c.Roles.FleetSource.Name)
	fleetProtection, e := kube.NewFleetConfigurationProtection(admin, probe, fp, fg)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	fleet, e := kube.NewProtectedFleetSettings(admin, fleetProtection, c.Roles.FleetSource.Name, c.Roles.FleetSource.UID, c.Roles.InstallationID)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	op, og := sourcePlan(c.OwnerGuard, c.Roles.OwnerSource.Name)
	ownerProtection, e := kube.NewOwnerConfigurationProtection(admin, probe, op, og)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	owner, e := kube.NewOwnerConfigurationSource(admin, ownerProtection, c.Roles.OwnerSource.Name, c.Roles.OwnerSource.UID, c.Roles.InstallationID)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	source, e := kube.NewConfigurationRoleSource(admin, protection, fleet, owner, c.Roles)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	root, e := kube.NewConfigurationRuntimeRoleRoot(ctx, source, c.Roles)
	if e != nil {
		return zero, configurationRoleProtectionUnavailable
	}
	defer root.Close()
	sql, e := in.sqlConfig(ctx, "sql-administrator.json")
	if e != nil || sql == nil {
		return zero, configurationRoleSQLUnavailable
	}
	producer, e := postgres.NewConfigurationRuntimeSQLRoles(ctx, sql.ConnConfig, root, c.Roles)
	if e != nil {
		return zero, configurationRoleSQLUnavailable
	}
	defer producer.Close()
	// A prior launch, including an uncertain one, permanently selects the
	// read-only replay branch. It must not reopen SQL or projection creation.
	previous, readErr := root.ReadConfigurationRuntimeRoles(ctx)
	if readErr != nil && !apierrors.IsNotFound(readErr) {
		return zero, configurationRoleProtectionUnavailable
	}
	if readErr == nil && previous.State.Launch != nil {
		if c.Launch == nil || previous.State.Launch.Configuration != c.Launch.Configuration || previous.State.Launch.Providers != c.Launch.Providers {
			return zero, configurationRoleLaunchUnavailable
		}
		if e = verifyConfigurationReconcilerLaunch(ctx, root, producer); e != nil {
			return zero, e
		}
		return contracts.WorkerObjectReference{Name: "asservat-configuration-runtime-" + strings.ReplaceAll(c.Roles.InstallationID, "-", ""), UID: previous.State.Launch.ProjectionUID}, nil
	}
	if _, e = producer.Provision(ctx); e != nil {
		return zero, configurationRoleSQLUnavailable
	}
	var ref contracts.WorkerObjectReference
	// Final SQL verification and projection use one explicit operation with
	// current rechecks. A prior successful provision result cannot renew the
	// original inventory observation for credential disclosure.
	e = root.WithConfigurationRoleOperation(ctx, func(call context.Context) error {
		verified, err := producer.VerifyConfigurationRuntimeRoles(call)
		if err != nil {
			return configurationRoleSQLUnavailable
		}
		ref, err = root.PublishConfigurationRuntimeProjection(call, verified)
		if err != nil {
			return configurationRoleProjectionUnavailable
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	if c.Launch != nil {
		// The effect and result verification are separate original operations.
		// An unknown effect reply may only be reconciled by exact readback.
		_ = root.WithConfigurationRoleOperation(ctx, func(call context.Context) error {
			verified, err := producer.VerifyConfigurationRuntimeRoles(call)
			if err != nil {
				return err
			}
			return root.LaunchConfigurationRuntime(call, verified, c.Launch.Configuration, c.Launch.Providers)
		})
		if e = verifyConfigurationReconcilerLaunch(ctx, root, producer); e != nil {
			return zero, e
		}
	}

	return ref, nil
}
func verifyConfigurationReconcilerLaunch(ctx context.Context, root *kube.ConfigurationRuntimeRoleRoot, producer *postgres.ConfigurationRuntimeSQLRoles) error {
	if e := root.WithConfigurationRoleOperation(ctx, func(call context.Context) error {
		verified, e := producer.VerifyLaunchedConfigurationRuntimeRoles(call)
		if e != nil {
			return e
		}
		return root.RecordConfigurationRuntimeLaunch(call, verified)
	}); e != nil {
		return configurationRoleLaunchUnavailable
	}
	return nil
}

func RunConfigurationRoleInstaller(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || disableWorkerCoreDumps() != nil {
		return configurationRoleInputInvalid
	}
	files, e := os.OpenRoot(contracts.ConfigurationRoleInstallerRoot)
	if e != nil {
		return configurationRoleInputInvalid
	}
	defer files.Close()
	call, end := context.WithTimeout(ctx, 30*time.Minute)
	defer end()
	if _, e = provisionConfigurationRoles(call, files); e != nil {
		return e
	}
	if call.Err() != nil {
		return configurationRoleProjectionUnavailable
	}
	return nil
}
func ConfigurationRoleInstallerRemedy(err error) string {
	var phase configurationRoleInstallerError
	code := "Unavailable"
	if errors.As(err, &phase) {
		switch phase {
		case configurationRoleInputInvalid, configurationRoleProtectionUnavailable, configurationRoleSQLUnavailable, configurationRoleProjectionUnavailable, configurationRoleLaunchUnavailable:
			code = string(phase)
		}
	}
	return "configuration-role-install: " + code + "; retain the original installation state and credentials, then check the protected input and current recovery status"
}
