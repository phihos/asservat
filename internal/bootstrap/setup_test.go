package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Secret volumes are symlinks into a hidden timestamped directory; setup
// indexes every component's sql-*.json by role name through them.
func TestReadRuntimeLoginsFollowsSecretVolumeLayout(t *testing.T) {
	root := t.TempDir()
	write := func(component, file string, c contracts.OwnerSQLCredential) {
		data := filepath.Join(root, component, "..2026_11_13")
		if err := os.MkdirAll(data, 0o700); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(c)
		if err := os.WriteFile(filepath.Join(data, file), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..2026_11_13", file), filepath.Join(root, component, file)); err != nil {
			t.Fatal(err)
		}
	}
	password := strings.Repeat("p", 43)
	write("hub-api", "sql-hub-runtime.json", contracts.OwnerSQLCredential{Username: "as_a_pub_01", Password: password})
	write("hub-worker", "sql-configuration-fleet.json", contracts.OwnerSQLCredential{Username: "as_a_cfg_00", Password: password})
	write("hub-worker", "sql-hub-runtime.json", contracts.OwnerSQLCredential{Username: "as_a_pub_01", Password: password})
	logins, err := readRuntimeLogins(root)
	if err != nil || len(logins) != 2 || logins["as_a_cfg_00"] != password {
		t.Fatal(logins, err)
	}
	write("publisher", "sql-hub-runtime.json", contracts.OwnerSQLCredential{Username: "as_a_pub_01", Password: strings.Repeat("q", 43)})
	if _, err = readRuntimeLogins(root); !errors.Is(err, cfg.ErrInvalid) {
		t.Fatal("conflicting passwords for one role accepted", err)
	}
}

func TestReadSetupIDsRequiresUUIDs(t *testing.T) {
	dir := t.TempDir()
	for i, key := range contracts.InstallationIDKeys() {
		v := fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1)
		if key == "issuerEpoch" {
			v = "10000000-0000-4000-8000-000000000099\n"
		}
		if err := os.WriteFile(filepath.Join(dir, key), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := readSetupIDs(dir)
	if err != nil || ids.IssuerEpoch != "10000000-0000-4000-8000-000000000099" {
		t.Fatal(ids, err)
	}
	if err = os.WriteFile(filepath.Join(dir, "clusterID"), []byte("cluster"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readSetupIDs(dir); err == nil {
		t.Fatal("non-UUID cluster accepted")
	}
}

func TestRunSetupArgumentsAndStepMessages(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"--wait-schema"}, {"--credential", "x"}, {"--ca", "x"}, {"extra"}, {"--timeout", "0s"}} {
		err := RunSetup(t.Context(), args, &out)
		var step *SetupStepError
		if !errors.As(err, &step) || step.Step != "arguments" {
			t.Fatal(args, err)
		}
	}
	err := RunSetup(t.Context(), []string{"--config", filepath.Join(t.TempDir(), "missing.json")}, &out)
	if err == nil || err.Error() != "setup stopped at configuration (invalid)" {
		t.Fatal(err)
	}
}

func TestSetupConfigurationIsClosed(t *testing.T) {
	valid := `{"format":"asservat-setup/v1","name":"asservat","namespace":"asservat","fleetSource":"asservat-fleet","postgres":{"host":"asservat-postgres.asservat.svc","port":5432,"database":"asservat"},"openBao":{"endpoint":"https://asservat-openbao.asservat.svc:8200","bundled":true,"accounts":{"hub-api":"asservat-hub-api"}},"objectStore":{"endpoint":"https://asservat-objectstore.asservat.svc:8333","region":"us-east-1","bundled":true,"auditBucket":"asservat-audit","evidenceBucket":"asservat-evidence"}}`
	c, err := contracts.DecodeSetupConfiguration(strings.NewReader(valid))
	if err != nil || !validSetupConfiguration(c) {
		t.Fatal(c, err)
	}
	if _, err = contracts.DecodeSetupConfiguration(strings.NewReader(strings.Replace(valid, `"name"`, `"extra":1,"name"`, 1))); err == nil {
		t.Fatal("unknown field accepted")
	}
	c.Name = "Invalid_Name"
	if validSetupConfiguration(c) {
		t.Fatal("invalid name accepted")
	}
}
