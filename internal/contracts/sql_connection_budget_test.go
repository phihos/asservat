package contracts

import (
	"errors"
	"testing"
)

func TestInstalledSQLConnectionBudget(t *testing.T) {
	one, err := InstalledSQLConnectionPlan(1)
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL defaults: 100 connections, three superuser slots.
	got, err := one.Validate(0, SQLServerCapacity{MaxConnections: 100, SuperuserReserved: 3})
	if err != nil || got.PerHubProcess != SQLConnectionsPerHubReplica || got.Required != 32+14*PublicRuntimeRetainedWorkerProcesses+len(PublicRuntimeFederationPurposes())*PublicRuntimeRetainedFederationProcesses+len(PublicRuntimePublisherPurposes())*PublicRuntimeRetainedPublisherProcesses+len(PublicRuntimeKeyServicePurposes())*PublicRuntimeRetainedKeyServiceProcesses+1+SQLMaintenanceReserve || got.Allocation != 97 || got.Available != 97 {
		t.Fatal("single-hub installed budget", got, err)
	}
	// Four retained hub processes (two replicas with surge) do not fit the defaults.
	four, _ := InstalledSQLConnectionPlan(PublicRuntimeRetainedHubProcesses)
	_, err = four.Validate(0, SQLServerCapacity{MaxConnections: 100, SuperuserReserved: 3})
	var budget *SQLConnectionBudgetError
	if !errors.As(err, &budget) || budget.Rule != "installation-allocation" || budget.Required != 4*32+28+len(PublicRuntimeFederationPurposes())*PublicRuntimeRetainedFederationProcesses+len(PublicRuntimePublisherPurposes())*PublicRuntimeRetainedPublisherProcesses+len(PublicRuntimeKeyServicePurposes())*PublicRuntimeRetainedKeyServiceProcesses+5 || budget.Configured != 97 || !errors.Is(err, ErrSQLConnectionBudget) {
		t.Fatal("rollout worst case accepted or misreported", err)
	}
	// A declared allocation cannot exceed the server's ordinary capacity.
	if _, err = one.Validate(98, SQLServerCapacity{MaxConnections: 100, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Rule != "allocation-exceeds-server" {
		t.Fatal("allocation above ordinary server capacity accepted", err)
	}
	// Reserved connections (PostgreSQL 16+) are not ordinary capacity either.
	if _, err = one.Validate(0, SQLServerCapacity{MaxConnections: 60, SuperuserReserved: 3, Reserved: 5}); !errors.As(err, &budget) || budget.Configured != 52 {
		t.Fatal("reserved connections counted as ordinary", err)
	}
	if _, err = InstalledSQLConnectionPlan(PublicRuntimeRetainedHubProcesses + 1); err == nil {
		t.Fatal("unsupported hub retention accepted")
	}
}

func TestSQLConnectionBudgetRejectsCompositionDefects(t *testing.T) {
	plan, _ := InstalledSQLConnectionPlan(1)
	over := plan
	over.Compartments = append([]SQLConnectionCompartment{}, plan.Compartments...)
	over.Compartments[0].Purposes = append(append([]string{}, plan.Compartments[0].Purposes...), "unplaced-purpose")
	// ADR-177: more purposes are fine under the governor cap; an ungoverned hub
	// or a cap above the per-replica allowance is a composition defect.
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); err != nil {
		t.Fatal("governed hub purpose rejected", err)
	}
	over.Compartments[0].MaxOpen = 0
	var budget *SQLConnectionBudgetError
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Rule != "per-hub-process" || budget.Required != len(over.Compartments[0].Purposes) {
		t.Fatal("ungoverned hub beyond the per-replica allowance accepted", err)
	}
	over.Compartments[0].MaxOpen = SQLConnectionsPerHubReplica + 1
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Rule != "per-hub-process" || budget.Required != 33 {
		t.Fatal("governor cap above the per-replica allowance accepted", err)
	}
	over.Compartments[0].MaxOpen = len(over.Compartments[0].Purposes) + 1
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); err == nil || errors.As(err, &budget) {
		t.Fatal("governor cap above the purpose count accepted", err)
	}
	dup := plan
	dup.Compartments = append([]SQLConnectionCompartment{}, plan.Compartments...)
	dup.Compartments[1].Purposes = append(append([]string{}, plan.Compartments[1].Purposes...), plan.Compartments[1].Purposes[0])
	if _, err := dup.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); err == nil {
		t.Fatal("double-counted purpose accepted")
	}
	if _, err := (SQLConnectionPlan{}).Validate(0, SQLServerCapacity{MaxConnections: 100}); err == nil {
		t.Fatal("empty plan accepted")
	}
}
