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
	// A superuser connection opened first also consumes ordinary admission
	// headroom. Budget the fixture observer separately, then keep the server's
	// reserve free regardless of connection order.
	out := fixtureBudget{Plan: plan, RequiredOrdinary: budget.Required, SuperuserReserved: 3, FixtureAdminConnections: 1}
	out.MaxConnections = out.RequiredOrdinary + out.FixtureAdminConnections + out.SuperuserReserved + out.Reserved
	_, err = plan.Validate(0, contracts.SQLServerCapacity{MaxConnections: out.MaxConnections, SuperuserReserved: out.SuperuserReserved})
	return out, err
}

func main() {
	budget, err := installedFixtureBudget()
	if err != nil || json.NewEncoder(os.Stdout).Encode(budget) != nil {
		os.Exit(1)
	}
}
