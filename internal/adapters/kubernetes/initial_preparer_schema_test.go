package kubernetes

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialSchemaRequiresExplicitClosedProfileAndImmutableBinding(t *testing.T) {
	legacy := handoverTestPlan()
	raw, e := json.Marshal(legacy)
	if e != nil || strings.Contains(string(raw), "schemaInitialization") {
		t.Fatal("legacy plan bytes gained schema authority")
	}
	p := legacy
	p.SchemaInitialization = contracts.InitialSchemaProtocol
	if !validPreparerPlan(p) {
		t.Fatal("qualified profile rejected")
	}
	bad := p
	bad.Handover = ""
	if validPreparerPlan(bad) {
		t.Fatal("unqualified schema capability")
	}
	s := &InitialPreparer{plan: p}
	now := time.Now().UTC().Truncate(time.Microsecond)
	w := contracts.InitialPreparationRoot{RootUID: ownerID(1), Schema: &contracts.InitialPreparationSchema{AttemptID: ownerID(2), BundleDigest: strings.Repeat("a", 64), Head: 48, DatabaseOID: 12000, PostmasterAt: now.Add(-time.Minute), DDLRole: contracts.InitialSQLHistoryManager{Name: "ddl", OID: 10}, Manager: *p.HistoryManager, ClaimedAt: now}}
	if !s.validSchema(w) {
		t.Fatal("original binding rejected")
	}
	mutations := map[string]func(*contracts.InitialPreparationRoot){
		"early-create":         func(w *contracts.InitialPreparationRoot) { w.Creates = []contracts.InitialPreparationCreate{{}} },
		"early-activation":     func(w *contracts.InitialPreparationRoot) { w.Activation = &contracts.InitialPreparationActivation{} },
		"manager-replacement":  func(w *contracts.InitialPreparationRoot) { w.Schema.Manager.OID++ },
		"ddl-manager-alias":    func(w *contracts.InitialPreparationRoot) { w.Schema.DDLRole = w.Schema.Manager },
		"changed-bundle-shape": func(w *contracts.InitialPreparationRoot) { w.Schema.BundleDigest = "not-a-digest" },
		"pre-claim-complete":   func(w *contracts.InitialPreparationRoot) { x := now.Add(-time.Second); w.Schema.CompletedAt = &x },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := w
			v := *w.Schema
			x.Schema = &v
			mutate(&x)
			if s.validSchema(x) {
				t.Fatal("invalid schema binding accepted")
			}
		})
	}
	complete := now.Add(time.Second)
	w.Schema.CompletedAt = &complete
	w.Creates = []contracts.InitialPreparationCreate{{}}
	if !s.validSchema(w) {
		t.Fatal("completed schema cannot precede declaration")
	}
	old := &InitialPreparer{plan: legacy}
	if old.validSchema(w) {
		t.Fatal("old plan adopted schema capability")
	}
}

func TestInitialSchemaRootCASGatesDeclarationAndPreservesOriginal(t *testing.T) {
	p := handoverTestPlan()
	p.SchemaInitialization = contracts.InitialSchemaProtocol
	f := newPreparerFixturePlan(t, "", p)
	var fleet contracts.FleetSettings
	raw, e := os.ReadFile("../../../examples/fleet-settings.json")
	if e != nil || json.Unmarshal(raw, &fleet) != nil {
		t.Fatal("synthetic fleet unavailable")
	}
	fleet.InstallationID = p.InstallationID
	f.config.Services = &contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: f.server.URL, Roots: [][]byte{f.server.Certificate().Raw}}, Postgres: contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: [][]byte{f.server.Certificate().Raw}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: [][]byte{f.server.Certificate().Raw}, Region: "test", Bucket: "audit"}, KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: [][]byte{f.server.Certificate().Raw}, AuditMount: "transit", AuditKey: "audit"}}
	f.config.SQLMaterial = &contracts.WorkerObjectReference{Name: "sql-material", UID: ownerID(910)}
	f.config.Providers = &contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "provider-material", UID: ownerID(911)}, IssuerPolicy: "issuer", WrapRole: "wrap-role", WrapPolicy: "wrap-policy", UnwrapRole: "unwrap-role", UnwrapPolicy: "unwrap-policy"}
	s := f.preparer(t)
	defer s.Close()
	ctx := context.Background()
	opened, e := s.Open(ctx)
	if e != nil {
		t.Fatal("root open", e)
	}
	if _, e = s.EnsureNext(ctx); e == nil {
		t.Fatal("declaration bypassed schema completion")
	}
	v := contracts.InitialPreparationSchema{BundleDigest: strings.Repeat("b", 64), Head: 48, DatabaseOID: 12000, PostmasterAt: time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute), DDLRole: contracts.InitialSQLHistoryManager{Name: "postgres", OID: 10}, Manager: *p.HistoryManager}
	claimed, _, e := s.ClaimInitialSchema(ctx, v)
	if e != nil || claimed.Schema == nil || claimed.RootUID != opened.RootUID {
		t.Fatal("original claim", e)
	}
	original := *claimed.Schema
	if _, _, e = s.ClaimInitialSchema(ctx, v); e == nil {
		t.Fatal("second original claim")
	}
	if _, e = s.EnsureNext(ctx); e == nil {
		t.Fatal("incomplete schema allowed declaration")
	}
	bad := original
	bad.DatabaseOID++
	if _, _, e = s.CompleteInitialSchema(ctx, bad); e == nil {
		t.Fatal("completion changed original database")
	}
	completed, _, e := s.CompleteInitialSchema(ctx, original)
	if e != nil || completed.Schema.CompletedAt == nil {
		t.Fatal("completion", e)
	}
	after, e := s.EnsureNext(ctx)
	if e != nil || after.Schema == nil || !equalJSON(after.Schema, completed.Schema) {
		t.Fatal("declaration lost schema provenance", e)
	}
	reopened, _, e := s.ReadInitialSchema(ctx)
	if e != nil || !equalJSON(reopened.Schema, completed.Schema) {
		t.Fatal("read reset schema provenance", e)
	}
}
