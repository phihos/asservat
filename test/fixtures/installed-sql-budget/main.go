//go:build ignore

// Command installed-sql-budget prints only the compiled installed connection
// plan and the owned fixture's server settings. It performs no external I/O.
package main

import (
	"encoding/json"
	"os"

	"asservat.local/asservat/internal/contracts"
)

type fixtureBudget struct {
	Plan                    contracts.SQLConnectionPlan `json:"plan"`
	RequiredOrdinary        int                         `json:"requiredOrdinary"`
	MaxConnections          int                         `json:"maxConnections"`
	SuperuserReserved       int                         `json:"superuserReserved"`
	Reserved                int                         `json:"reserved"`
	FixtureAdminConnections int                         `json:"fixtureAdminConnections"`
}

func installedFixtureBudget() (fixtureBudget, error) {
	plan, err := contracts.InstalledSQLConnectionPlan(1)
	if err != nil {
		return fixtureBudget{}, err
	}
	// Validate computes the allowance from the real purpose/process inventory.
	// This large value is arithmetic input only, never a server setting.
	budget, err := plan.Validate(0, contracts.SQLServerCapacity{MaxConnections: 100000})
	if err != nil {
		return fixtureBudget{}, err
	}
	// The fixture's single administrator uses one of PostgreSQL's three
	// explicit superuser slots. No extra ordinary slots or pool cap are added.
	out := fixtureBudget{Plan: plan, RequiredOrdinary: budget.Required, MaxConnections: budget.Required + 3, SuperuserReserved: 3, FixtureAdminConnections: 1}
	_, err = plan.Validate(0, contracts.SQLServerCapacity{MaxConnections: out.MaxConnections, SuperuserReserved: out.SuperuserReserved})
	return out, err
}

func main() {
	budget, err := installedFixtureBudget()
	if err != nil || json.NewEncoder(os.Stdout).Encode(budget) != nil {
		os.Exit(1)
	}
}
