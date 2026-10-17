package postgres

import (
	"asservat.local/asservat/internal/contracts"
	"encoding/base64"
	"strings"
	"testing"
)

func TestInitialHistoryLoginIsInstallationAndPurposeBound(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	name, e := InitialSQLHistoryRoleName(id)
	if e != nil {
		t.Fatal(e)
	}
	value := InitialSQLLogin{Username: name, Password: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	if !ValidInitialSQLHistoryLogin(id, value) {
		t.Fatal("valid fixed input rejected")
	}
	for _, role := range []string{"prepare", "audit", "activate"} {
		other := value
		other.Username = initialRoleName(id, role)
		if ValidInitialSQLHistoryLogin(id, other) {
			t.Fatal("temporary role accepted as passive history")
		}
	}
	for _, password := range []string{"", strings.Repeat("a", 32), value.Password + "=", strings.Repeat("a", 44)} {
		other := value
		other.Password = password
		if ValidInitialSQLHistoryLogin(id, other) {
			t.Fatal("noncanonical private password accepted")
		}
	}
	if ValidInitialSQLHistoryLogin("00000000-0000-4000-8000-000000000002", value) {
		t.Fatal("installation crossed")
	}
	for _, g := range initialHistoryGrants() {
		if g.kind == "schema" {
			if g.privilege != "USAGE" {
				t.Fatal("DDL privilege")
			}
		} else if g.privilege != "SELECT" || g.object != "goose_db_version" && g.object != "fleet_initial_activation" || g.column != "" {
			t.Fatal("history role can mutate or read unrelated authority")
		}
	}
}

func TestInitialHistoryManagerIsAnIndependentFinitePin(t *testing.T) {
	pin := contracts.InitialSQLHistoryManager{Name: "original_setup_manager", OID: 12345}
	if !validInitialHistoryManager(pin) {
		t.Fatal("original pin rejected")
	}
	for _, bad := range []contracts.InitialSQLHistoryManager{{}, {Name: pin.Name}, {Name: pin.Name, OID: 10}, {Name: "", OID: pin.OID}, {Name: "manager\x00", OID: pin.OID}, {Name: strings.Repeat("m", 64), OID: pin.OID}} {
		if validInitialHistoryManager(bad) {
			t.Fatal("invalid manager identity accepted")
		}
	}
}
