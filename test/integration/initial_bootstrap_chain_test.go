package integration

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func initialBootstrapAdminPoolConfig(dsn string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// Only the installed continuation's sequential observer uses one reserved
	// superuser slot. Other bootstrap modes deliberately hold an admin lock
	// while observing through another connection and retain their old pool.
	if os.Getenv("ASSERVAT_INSTALLER_CONTINUATION") == "1" {
		config.MaxConns, config.MinConns = 1, 0
	}
	return config, nil
}

func TestInitialBootstrapAdminPoolKeepsBlockingModes(t *testing.T) {
	const dsn = "postgres://fixture@127.0.0.1/fixture?sslmode=disable"
	original, err := pgxpool.ParseConfig(dsn)
	if err != nil || original.MaxConns < 2 {
		t.Fatal("original component pool must support blocking lock tests", err)
	}
	for _, mode := range []string{"", "1"} {
		t.Run("installed="+mode, func(t *testing.T) {
			t.Setenv("ASSERVAT_INSTALLER_CONTINUATION", mode)
			got, err := initialBootstrapAdminPoolConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			want := original.MaxConns
			if mode == "1" {
				want = 1
			}
			if got.MaxConns != want || got.MinConns != original.MinConns {
				t.Fatal("component and installed observer pool profiles differ", got.MaxConns, got.MinConns)
			}
		})
	}
}

// installedClusterCount is the hub plus its workload clusters: two for the
// focused runs that use one workload cluster, three otherwise.
func installedClusterCount() int {
	if f := installedJourneyFocus(); f == "restart" || f == "journey" || f == "browser" || f == "upgrade" || f == "policy" || f == "alert" || f == "logresource" || f == "chain" || f == "share" || f == "approved-recording" || f == "manual-logs" || f == "manual-syscall" || f == "manual-arguments" || f == "manual-mixed" || f == "manual-raw" || f == "manual-http" || f == "manual-peers" || installedProfileFocus() || f == "native-paced" || f == "policy-recording" || f == "policy-arguments" || f == "policy-profile" || installedOngoingFocus() || f == "journey-store-failure" || f == "journey-start-failure" || f == "retention-shortening" || f == "early-erasure" || f == "processing-workload" || f == "privacy-inventory" || f == "share-retirement" {
		return 2
	}
	return 3
}
