package contracts

import (
	"errors"
	"fmt"
	"slices"
)

// specs/persistence.md: at most 32 pooled connections per hub replica, with an
// installation-wide allocation that leaves maintenance headroom.
const SQLConnectionsPerHubReplica = 32

// SQLMaintenanceReserve keeps ordinary connections free for the separate DDL
// migration role (1), a backup/restore tool such as pgBackRest (2) and one
// operator/monitoring session. PostgreSQL's superuser reserve is separate.
const SQLMaintenanceReserve = 4

var ErrSQLConnectionBudget = errors.New("PostgreSQL connection budget insufficient")

// SQLConnectionCompartment is one fixed process kind. Every product purpose
// owns one MaxConns=1 pool per process; RetainedProcesses is the selected
// worst case including rollout surge and closing processes. MaxOpen, when set,
// is the process's connection governor cap (ADR-177): its purposes keep their
// own logins, but at most MaxOpen of them hold a physical connection at once.
type SQLConnectionCompartment struct {
	Name              string
	Purposes          []string
	RetainedProcesses int
	MaxOpen           int
	Hub               bool
}

// open is the most physical connections one process of c can hold.
func (c SQLConnectionCompartment) open() int {
	if c.MaxOpen > 0 {
		return c.MaxOpen
	}
	return len(c.Purposes)
}

// SQLConnectionPlan is derived from the selected immutable deployment graph,
// never from an observed idle count. Verifiers are installer login checks
// active at the same time (the installers serialize them).
type SQLConnectionPlan struct {
	Compartments []SQLConnectionCompartment
	Verifiers    int
	Reserve      int
}

// SQLServerCapacity is read from the actual qualified server settings.
type SQLServerCapacity struct {
	MaxConnections, SuperuserReserved, Reserved int
}

func (s SQLServerCapacity) Ordinary() int {
	return s.MaxConnections - s.SuperuserReserved - s.Reserved
}

// SQLConnectionBudget reports required and configured counts for operators.
type SQLConnectionBudget struct {
	PerHubProcess, Required, Allocation, Available int
}

// SQLConnectionBudgetError names the failed rule with exact counts and a
// supported remedy. It never suggests raising a limit automatically.
type SQLConnectionBudgetError struct {
	Rule                 string
	Required, Configured int
}

func (e *SQLConnectionBudgetError) Error() string {
	remedy := "reduce desired hub replicas or rollout surge, or raise the PostgreSQL connection allocation"
	if e.Rule == "per-hub-process" {
		remedy = "the selected hub purposes exceed the per-replica allowance; this is a product composition defect"
	}
	return fmt.Sprintf("%s: %s requires %d connections, %d configured; %s", ErrSQLConnectionBudget, e.Rule, e.Required, e.Configured, remedy)
}
func (e *SQLConnectionBudgetError) Unwrap() error { return ErrSQLConnectionBudget }

// InstalledSQLConnectionPlan returns the currently composed installed purposes:
// the public hub and owner identity per hub process, and configuration,
// capacity and capture-cleanup purposes per hub-worker process. The worst case
// includes the downloads logins of ADR-204 (worker configuration acceptance
// and acquisition unwraps), which open only with their deployment sections.
func InstalledSQLConnectionPlan(hubProcesses int) (SQLConnectionPlan, error) {
	if hubProcesses < 1 || hubProcesses > PublicRuntimeRetainedHubProcesses {
		return SQLConnectionPlan{}, ErrSQLConnectionBudget
	}
	hub := append(PublicRuntimeHubRolePurposes(), OwnerIdentityRolePurposes()...)
	worker := append(ConfigurationRuntimeRolePurposes(), "capacity", "capacity-capture")
	worker = append(worker, PublicRuntimePermissionPurposes()...)
	worker = append(worker, PublicRuntimeRetentionPurposes()...)
	worker = append(worker, PublicRuntimeWorkerConfigurationPurposes()...)
	worker = append(worker, PublicRuntimeCaptureCleanupPurposes()...)
	return SQLConnectionPlan{Compartments: []SQLConnectionCompartment{
		{Name: "hub", Purposes: hub, RetainedProcesses: hubProcesses, MaxOpen: SQLConnectionsPerHubReplica, Hub: true},
		{Name: "hub-worker", Purposes: worker, RetainedProcesses: PublicRuntimeRetainedWorkerProcesses},
		{Name: "hub-federation", Purposes: PublicRuntimeFederationPurposes(), RetainedProcesses: PublicRuntimeRetainedFederationProcesses},
		{Name: "publisher", Purposes: PublicRuntimePublisherPurposes(), RetainedProcesses: PublicRuntimeRetainedPublisherProcesses},
		{Name: "key-service", Purposes: PublicRuntimeKeyServicePurposes(), RetainedProcesses: PublicRuntimeRetainedKeyServiceProcesses},
	}, Verifiers: 1, Reserve: SQLMaintenanceReserve}, nil
}

// Validate checks the per-hub allowance, the declared installation allocation
// (zero selects the server's whole ordinary capacity) and the actual server.
func (p SQLConnectionPlan) Validate(allocation int, server SQLServerCapacity) (SQLConnectionBudget, error) {
	var out SQLConnectionBudget
	if len(p.Compartments) == 0 || p.Verifiers < 0 || p.Reserve < 0 || allocation < 0 || server.MaxConnections < 1 || server.SuperuserReserved < 0 || server.Reserved < 0 {
		return out, ErrSQLConnectionBudget
	}
	for _, c := range p.Compartments {
		if c.Name == "" || c.RetainedProcesses < 1 || len(c.Purposes) == 0 || c.MaxOpen < 0 || c.MaxOpen > len(c.Purposes) {
			return out, ErrSQLConnectionBudget
		}
		unique := slices.Clone(c.Purposes)
		slices.Sort(unique)
		if len(slices.Compact(unique)) != len(c.Purposes) {
			return out, ErrSQLConnectionBudget // a purpose counted twice is a composition defect
		}
		if c.Hub {
			out.PerHubProcess = max(out.PerHubProcess, c.open())
		}
		out.Required += c.RetainedProcesses * c.open()
	}
	out.Required += p.Verifiers + p.Reserve
	out.Available = server.Ordinary()
	out.Allocation = allocation
	if allocation == 0 {
		out.Allocation = out.Available
	}
	switch {
	case out.PerHubProcess > SQLConnectionsPerHubReplica:
		return out, &SQLConnectionBudgetError{"per-hub-process", out.PerHubProcess, SQLConnectionsPerHubReplica}
	case out.Allocation > out.Available:
		return out, &SQLConnectionBudgetError{"allocation-exceeds-server", out.Allocation, out.Available}
	case out.Required > out.Allocation:
		return out, &SQLConnectionBudgetError{"installation-allocation", out.Required, out.Allocation}
	}
	return out, nil
}
