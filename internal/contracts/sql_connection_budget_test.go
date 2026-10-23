package contracts

import (
	"errors"
	"slices"
	"testing"
)

func TestInstalledSQLConnectionBudgetCoversPermissionProjection(t *testing.T) {
	plan, err := InstalledSQLConnectionPlan(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("all enabled worker pools", func(t *testing.T) {
		worker := slices.IndexFunc(plan.Compartments, func(c SQLConnectionCompartment) bool {
			return c.Name == "hub-worker"
		})
		if worker < 0 {
			t.Fatal("worker compartment missing")
		}
		// The permission worker opens one independent connection for each
		// selected purpose. None shares the hub's connection governor.
		for _, purpose := range PermissionProjectionPurposes(true, true, true, true) {
			if !slices.Contains(plan.Compartments[worker].Purposes, purpose) {
				t.Errorf("worker pool %q missing from installed connection budget", purpose)
			}
		}
	})
	t.Run("browser observer cannot spend maintenance headroom", func(t *testing.T) {
		_, err := plan.Validate(0, SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3})
		var budget *SQLConnectionBudgetError
		if !errors.As(err, &budget) || budget.Rule != "installation-allocation" || budget.Required != 114 || budget.Configured != 112 {
			t.Fatal("budget without the two retained browser observers accepted or misreported", err)
		}
	})
}

func TestInstalledSQLConnectionBudget(t *testing.T) {
	one, err := InstalledSQLConnectionPlan(1)
	if err != nil {
		t.Fatal(err)
	}
	// The hub-worker holds 20 logins per retained process, and the key
	// service 4: ADR-204 added two worker configuration logins and the
	// acquisition login (101), and ADR-205 the three context deletion logins
	// (107). Five simultaneous installer pools brought the allowance to 112;
	// ADR-210's browser observer adds one per retained worker, reaching 114.
	required := 32 + 20*PublicRuntimeRetainedWorkerProcesses + len(PublicRuntimeFederationPurposes())*PublicRuntimeRetainedFederationProcesses + len(PublicRuntimePublisherPurposes())*PublicRuntimeRetainedPublisherProcesses + len(PublicRuntimeKeyServicePurposes())*PublicRuntimeRetainedKeyServiceProcesses + 5 + 1 + SQLMaintenanceReserve
	// PostgreSQL defaults (100 connections, three superuser slots) no longer
	// hold that worst case; the error names the exact counts.
	_, err = one.Validate(0, SQLServerCapacity{MaxConnections: 100, SuperuserReserved: 3})
	var budget *SQLConnectionBudgetError
	if required != 114 || !errors.As(err, &budget) || budget.Rule != "installation-allocation" || budget.Required != required || budget.Configured != 97 {
		t.Fatal("single-hub worst case accepted or misreported at the defaults", err)
	}
	// The installer is separate from both the verifier and maintenance reserve.
	installer := one.Compartments[len(one.Compartments)-1]
	if installer.Name != "installer" || installer.RetainedProcesses != 1 || installer.open() != 5 || one.Verifiers != 1 || one.Reserve != SQLMaintenanceReserve {
		t.Fatal("installer allowance borrowed verifier or maintenance capacity", one)
	}
	// Retained runtime plus installer needs max_connections of at least 117.
	if _, err = one.Validate(0, SQLServerCapacity{MaxConnections: 116, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Required != 114 || budget.Configured != 113 {
		t.Fatal("single-hub worst case accepted below 117 connections", err)
	}
	got, err := one.Validate(0, SQLServerCapacity{MaxConnections: 117, SuperuserReserved: 3})
	if err != nil || got.PerHubProcess != SQLConnectionsPerHubReplica || got.Required != required || got.Allocation != 114 || got.Available != 114 {
		t.Fatal("single-hub installed budget", got, err)
	}
	// Four retained hub processes (two replicas with surge) do not fit the defaults.
	four, _ := InstalledSQLConnectionPlan(PublicRuntimeRetainedHubProcesses)
	_, err = four.Validate(0, SQLServerCapacity{MaxConnections: 100, SuperuserReserved: 3})
	if !errors.As(err, &budget) || budget.Rule != "installation-allocation" || budget.Required != required+3*32 || budget.Configured != 97 || !errors.Is(err, ErrSQLConnectionBudget) {
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
	// A shared credential may back several pool slots. A governor can cap a
	// compiled 33-slot pool plan at 32; removing that cap must fail even though
	// the credential count is small.
	over.Compartments[0].PoolCapacity = SQLConnectionsPerHubReplica + 1
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); err != nil {
		t.Fatal("governed hub purpose rejected", err)
	}
	over.Compartments[0].MaxOpen = 0
	var budget *SQLConnectionBudgetError
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Rule != "per-hub-process" || budget.Required != 33 {
		t.Fatal("ungoverned hub beyond the per-replica allowance accepted", err)
	}
	over.Compartments[0].MaxOpen = SQLConnectionsPerHubReplica + 1
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); !errors.As(err, &budget) || budget.Rule != "per-hub-process" || budget.Required != 33 {
		t.Fatal("governor cap above the per-replica allowance accepted", err)
	}
	over.Compartments[0].MaxOpen = over.Compartments[0].PoolCapacity + 1
	if _, err := over.Validate(0, SQLServerCapacity{MaxConnections: 1000, SuperuserReserved: 3}); err == nil || errors.As(err, &budget) {
		t.Fatal("governor cap above the compiled pool capacity accepted", err)
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
