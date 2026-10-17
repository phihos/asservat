package bootstrap

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestInitialPreparationActiveSchemaPreflightRejectsChangedIncarnation(t *testing.T) {
	calls := 0
	err := initialPreparationSchemaPreflight(context.Background(), contracts.InitialSchemaProtocol, func(ctx context.Context) (time.Time, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded constructor preflight")
		}
		return time.Time{}, cfg.ErrChanged
	}, time.Now)
	if !errors.Is(err, cfg.ErrChanged) || calls != 1 {
		t.Fatal("active constructor ignored original schema incarnation")
	}
}
func TestInitialPreparationSchemaPreflightPreservesOriginalDeadlineAndLegacy(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	if err := initialPreparationSchemaPreflight(context.Background(), "", func(context.Context) (time.Time, error) {
		t.Fatal("legacy gained schema lookup")
		return time.Time{}, nil
	}, clock); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"shorter", "parent", "changed-capability", "missing"} {
		t.Run(mode, func(t *testing.T) {
			now = time.Now()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			verify := func(context.Context) (time.Time, error) {
				until := now.Add(time.Second)
				if mode == "parent" {
					stop()
				} else {
					now = until
				}
				return until, nil
			}
			capability := contracts.InitialSchemaProtocol
			if mode == "changed-capability" {
				capability = "unknown"
			}
			if mode == "missing" {
				verify = nil
			}
			if err := initialPreparationSchemaPreflight(ctx, capability, verify, clock); err == nil {
				t.Fatal("stale or missing preflight accepted")
			}
		})
	}
}

func TestInitialInstallerSchemaBindingIsClosedAndChangesProtectedPlan(t *testing.T) {
	in, dir, c := initialInputFixture(t)
	raw, _ := json.Marshal(c)
	if bytes.Contains(raw, []byte(`"schema"`)) || bytes.Contains(raw, []byte(`"schemaInitialization"`)) {
		t.Fatal("legacy projection changed")
	}
	b, err := postgres.EmbeddedInitialSchema()
	if err != nil {
		t.Fatal(err)
	}
	c.Handover = contracts.InitialPreparationHandoverProtocol
	c.SchemaInitialization = contracts.InitialSchemaProtocol
	c.Schema = &contracts.InitialSchemaExpectation{BundleDigest: b.Digest, Head: b.Head, DatabaseOID: 123, PostmasterAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)}
	writeOwnerJSON(t, dir, "deployment.json", c)
	original, err := readInitialInputs(context.Background(), in.files)
	if err != nil {
		t.Fatal(err)
	}
	c.Schema.DatabaseOID++
	writeOwnerJSON(t, dir, "deployment.json", c)
	changed, err := readInitialInputs(context.Background(), in.files)
	if err != nil || changed.plan == original.plan {
		t.Fatal("database binding excluded from protected plan", err)
	}
	for _, mode := range []string{"missing-binding", "missing-capability", "changed-capability", "changed-bundle", "changed-head", "zero-oid", "sub-microsecond", "missing-handover"} {
		t.Run(mode, func(t *testing.T) {
			v := c
			binding := *c.Schema
			v.Schema = &binding
			switch mode {
			case "missing-binding":
				v.Schema = nil
			case "missing-capability":
				v.SchemaInitialization = ""
			case "changed-capability":
				v.SchemaInitialization = "future"
			case "changed-bundle":
				v.Schema.BundleDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "changed-head":
				v.Schema.Head++
			case "zero-oid":
				v.Schema.DatabaseOID = 0
			case "sub-microsecond":
				v.Schema.PostmasterAt = v.Schema.PostmasterAt.Add(time.Nanosecond)
			case "missing-handover":
				v.Handover = ""
			}
			writeOwnerJSON(t, dir, "deployment.json", v)
			if _, err := readInitialInputs(context.Background(), in.files); err == nil {
				t.Fatal("incomplete or incompatible schema binding accepted")
			}
		})
	}
}
