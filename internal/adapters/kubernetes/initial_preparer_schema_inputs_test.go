package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestInitialPreparationFinalProjectionRequiresCompletedSchemaBinding(t *testing.T) {
	_, p := finalInputFixture(t, "healthy")
	w, err := p.PrepareFinalInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.inputConfiguration(w)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	if bytes.Contains(raw, []byte(`"schema"`)) || bytes.Contains(raw, []byte(`"schemaInitialization"`)) {
		t.Fatal("legacy fields changed")
	}
	p.plan.SchemaInitialization = contracts.InitialSchemaProtocol
	p.plan.HistoryManager = &contracts.InitialSQLHistoryManager{Name: "manager", OID: 123}
	now := time.Now().UTC().Truncate(time.Microsecond)
	w.Schema = &contracts.InitialPreparationSchema{AttemptID: ownerID(881), BundleDigest: strings.Repeat("ab", 32), Head: 48, DatabaseOID: 777, PostmasterAt: now.Add(-time.Hour), DDLRole: contracts.InitialSQLHistoryManager{Name: "ddl", OID: 124}, Manager: *p.plan.HistoryManager, ClaimedAt: now.Add(-time.Minute), CompletedAt: &now}
	c, err = p.inputConfiguration(w)
	if err != nil || c.Schema == nil || c.SchemaInitialization != contracts.InitialSchemaProtocol || c.Schema.BundleDigest != w.Schema.BundleDigest || c.Schema.Head != w.Schema.Head || c.Schema.DatabaseOID != w.Schema.DatabaseOID || !c.Schema.PostmasterAt.Equal(w.Schema.PostmasterAt) {
		t.Fatal("original completed schema omitted or changed", err)
	}
	original := *w.Schema
	for _, mode := range []string{"missing", "incomplete", "changed-manager", "legacy-adoption"} {
		t.Run(mode, func(t *testing.T) {
			copy := w
			v := original
			copy.Schema = &v
			p.plan.SchemaInitialization = contracts.InitialSchemaProtocol
			switch mode {
			case "missing":
				copy.Schema = nil
			case "incomplete":
				copy.Schema.CompletedAt = nil
			case "changed-manager":
				copy.Schema.Manager.OID++
			case "legacy-adoption":
				p.plan.SchemaInitialization = ""
			}
			if _, e := p.inputConfiguration(copy); e == nil {
				t.Fatal("unbound activation projection produced")
			}
		})
	}
}
